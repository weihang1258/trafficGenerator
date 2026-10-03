# #139 MySQL 设计契约

> 版本：v1.0.0（P-PIPE 文档轨，as-built）  
> 日期：2026-09-29  
> 配套：`docs/protocols/mysql/testcase.md`、`trafficgen/test/protocol_pcap/cases/mysql.json`  
> 实现证据：`trafficgen/internal/protocol/mysql/{planner.go,layer_gen.go}`、`internal/core/types.go`、`internal/core/strategy_convert.go`、`internal/core/layers/registry.go`。

## 1. 范围、证据与层链唯一真相

本契约描述 MySQL 8.0 风格经典协议（MySQL binary packet protocol）在 TCP 上的**声明式脚本回放**：TCP 三次握手、服务端 Greeting、客户端 Handshake Response、服务端 OK、按 `commands[]` 顺序的请求/回复、TCP 四次挥手。协议端口惯例为 3306；registry 的 FieldContract 只提供默认值，显式非标准端口不被 MySQL validator 拒绝。

权威优先级为：现有 cases JSON（唯一可执行契约）→ 当前 Go 实现与测试 → MySQL 官方 protocol overview / 8.0 internals 文档 → TCP RFC 9293、IPv6 RFC 8200。官方文档用于消息语义与字段规则；帧偏移和 tshark 字段以 case 的实测断言为准。

层链形状只有 `layers`、`flow_control` 与 `output`：地址在 `ip.src`/`ip.dst`，端口在 `tcp.src_port`/`tcp.dst_port`，数量在 `flow_control`；不得恢复顶层 `src_ip`、`dst_ip`、`src_port`、`dst_port`、`count` 或 `mysql` 映射。`mysql` 是 `CategoryTerminal`，依赖 `tcp`（registry.go:1606），默认 `tcp.dst_port=3306`；strategy_convert.go:1222 与 4628 负责翻译。当前唯一 case 已采用该形状。

### 1.1 门1：§1–§14 对照表

| 门 | as-built 满足方式与证据 |
|---|---|
| §1 范围/层链 | TCP 载体上的经典 MySQL 会话；本节、§2、§11；case `mysql-basic-session`。 |
| §2 规范依据 | MySQL 8.0 Protocol::Client/Server Protocol（packet header、握手、commands、OK/ERR/result）；TCP RFC 9293 / RFC 8200；实现 planner.go:528–889。 |
| §3 五件套 | 单 TCP 会话表见 §3.1；事件序列见 §3.2；请求/回复关联见 §3.3；插入位置见 §3.4；时间线见 §3.5。MySQL 当前 planner 只展开独立流，流关联不适用。 |
| §4 功能 | Greeting/auth/commands/OK/ERR/result/prepare/no-reply/raw 由 planner.go:1319–1447；当前 JSON 仅冒烟链，详见 testcase §2。 |
| §5 性能 | `segmentByMSS`（planner.go:1491–1508）按 TCP MSS 分段；MySQL 3-byte length 最大 0xFFFFFF；大结果/请求能力见 §7。 |
| §6 数据 | LE packet length/sequence、lenenc integer/string、握手字段、OK/ERR/column/row/binary row 见 §4–§6。 |
| §7 地址与流 | IPv4/IPv6 地址交由 ip 层；TCP 端口交由 tcp 层；默认/非默认端口约束见 §8 与 testcase；单流为当前实现，multi-flow 不适用。 |
| §8 业务 | 登录后命令脚本、OK/ERR/result-set/prepare 是典型数据库业务；当前可按序多事务，JSON 尚只有基础登录。 |
| §9 错误 | validator 错误锚词见 §9；负例尚未进入 cases，登记 G-MYSQL-1。 |
| §10 载体 | 纯 TCP；TLS 不实现，IPv4/IPv6 均由通用层承载；pcap/NIC 使用同一 case 契约（见 §10）。 |
| §11 存量审计 | 唯一当前 case 已层链化；旧 `trafficgen/docs/protocol-pcap-test/mysql.md` 为过期产物，按 §12.4 登记。 |
| §12 动态字段 | 完整清单见 §3.6；当前 MySQL sub-map 使用标量 parseMySQLConfig，不具备五策略展开，故登记缺口，不伪报已支持。 |
| §13 交付/三方 | design + testcase + cases 三方只有 `mysql-basic-session`；ID、场景、最小包数、字段/字节断言一致。 |
| §14 审查/状态 | 本稿自审见 §14；独立代码设计逻辑审查与用例覆盖审查待主线程执行；待实现边界不计当前覆盖。 |

### 1.2 §1 顶层旧键逐键去向与目标形

迁移已完成；下表保留为审计映射，说明旧键不得重新引入。

| 旧键 | 去向 |
|---|---|
| `src_ip` / `dst_ip` | `layers.ip.src` / `layers.ip.dst` |
| `src_port` / `dst_port` | `layers.tcp.src_port` / `layers.tcp.dst_port` |
| `count` | `flow_control.count`（实际任务展开字段） |
| `mysql` | `layers.mysql`，只作为终端层子映射 |

目标（完整的最小等价形）为：

```json
{"layers":{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"},"tcp":{"src_port":12345,"dst_port":3306},"mysql":{}},"flow_control":{"count":1}}
```

当前 `cases/mysql.json` 唯一正例已经是严格层链 `layers=[ip,tcp,mysql]`；§12 的动态字段缺口不影响本例的静态层链形状。

## 2. 业务场景与确定性边界

真实常用路径是客户端建立 TCP 连接，接收 server greeting，提交认证，再连续发 SQL/prepare/execute，读取 OK、ERR 或 result set，最后退出。配置是剧本：`commands[]` 逐项回放，不等待真实服务端输入；planner 自动生成对应的服务端回复。`ServerBypassAuth=true` 时跳过认证往返，适用于已认证重放。

默认值在 Plan/编码阶段填充：version `8.0.36`、thread_id `1`、auth plugin `mysql_native_password`、username `root`、charset `0x21`、max packet `0x01000000`、固定 scramble；MSS 为 1460、TTL 为 64。legacy planner 的随机 ISN/IP ID 不是业务字段，事件 layer generator 由 TCP 层负责握手、序号、MSS、挥手。

## 3. 五件套与动态字段

### 3.1 会话表

| 会话 | 载体 | 四元组 | 生命周期 |
|---|---|---|---|
| S1 | TCP | `ip.src:tcp.src_port → ip.dst:tcp.dst_port` | SYN → Greeting/auth → commands → FIN |

当前协议没有控制流派生数据流，故流关联不适用；`sessions[]`/并发会话不是当前 MySQL generator 的配置能力，不能写成已实现。

### 3.2 事务序列

一个会话的事件序列为：`TCP_SYN`、`TCP_SYN_ACK`、`TCP_ACK`、`Greeting(seq=0,down)`、`HandshakeResponse(seq=1,up)`、`AuthOK(seq=2,down)`、对每个 command 的 `Request(seq=0,up)` + `Reply(seq=1..N,down)`、`FIN/ACK/FIN/ACK`。命令顺序就是事务顺序；单个请求的 response 不携带独立 transaction ID，按 TCP 会话和 MySQL packet sequence 关联。

### 3.3 关联关系

命令请求通过同一 TCP 四元组和方向关联响应；应用包的 1-byte sequence 从请求/握手阶段的规定值开始。result-set 的 column count、column definitions、EOF、rows、EOF 按同一 response 序列关联。`COM_STMT_EXECUTE` 通过 `StmtID` 关联此前 prepare（当前 validator 只要求非零，不验证跨 command 是否曾 prepare）。

### 3.4 插入位置

- Greeting：TCP ACK 之后第一条 down 应用负载。
- auth：Greeting 后 up，再 down。
- 每个 command：前一 response 完毕后插入 up request，再插入全部 down reply。
- teardown：全部 command reply 之后，由 TCP 层生成器插入。

### 3.5 时间线

时间戳由 planner 为 flow 取单一 `now`，所有 legacy PacketConfig 共享该时间；layer event 模式只交付消息事件，TCP 层决定 transport timing。没有 keep-alive、重试或重连自动调度。

### 3.6 §12 动态字段清单（当前能力与算法）

| 字段 | 类型/写法契约 | 序号算法/代码位置 | 当前状态 |
|---|---|---|---|
| `ip.src`、`ip.dst` | fixed/inc/rand/list/pattern 应按统一策略取值 | 通用 strategy 层；mysql 不读取策略 | 当前 mysql 标量 parse，待策略接线 |
| `tcp.src_port`、`tcp.dst_port` | 同上 | 通用 tcp 层 | 当前 mysql 不提供动态读取 |
| `server_version`、`username`、`database` | 文本业务字段 | `encodeGreetingPayload` 528、`encodeHandshakeResponsePayload` 604 | fixed 标量 |
| `thread_id`、`character_set`、`max_packet_size` | 数值字段 | 同上 | fixed 标量 |
| `scramble`、`password` | bytes/text | `normalizedScramble` 680、`computeAuthResponse` 911 | fixed 标量 |
| `commands[].body`、`reply_bytes` | text/hex/base64 | `decodeUserBytes` 1450 | fixed per command |
| command/result 字段 | opcode、rows、column defs、StmtID 等 | `buildReplyPackets` 1319、编码器 774–1315 | fixed per command |

按 §10.4，inc 回绕、rand 可复现、list 轮转、pattern 替换、静态复制拒绝五类动态测试均为待实现边界（G-MYSQL-2），不可计入已覆盖行为。当前 `parseMySQLConfig`（strategy_convert.go:4628）只读普通 JSON 标量和数组。

## 4. MySQL packet 通用线格式

每个应用包为 `3B little-endian payload_length + 1B sequence_id + payload`，总长 `4 + payload_length`；payload length 的合法最大值为 `2^24-1=16,777,215`。`framePacket` 在 planner.go:874–887 实现。多字节协议整数默认为 little-endian；lenenc integer 使用 1B（<251）、`fc+2B`、`fd+3B`、`fe+8B` 前缀规则；lenenc string 为 lenenc integer + bytes。

TCP payload 超过 MSS 时，`segmentByMSS` 每段不超过 MSS，TCP sequence 按段 payload 长度递增；应用 packet header 不因 MSS 分段重写。

## 5. Greeting 与认证字段

### 5.1 Server Greeting（down）

按顺序：`protocol_version(1)=0x0a`；`server_version` NUL；`thread_id(4 LE)`；`auth_plugin_data_part1(8)`；filler(1)；capability lower(2 LE)；character_set(1)；status_flags(2 LE, 默认 0x0002)；capability upper(2 LE)；auth_data_length(1, 21)；reserved(10)；auth part2(12)+NUL；auth plugin NUL。固定部分（含 `server_version` 的 NUL、但不含 version/plugin 文本及 plugin 的 NUL）= 1+1+4+8+1+2+1+2+2+1+10+13 = 46B；完整 body = 46 + `len(version)` + `len(plugin)` + 1。默认 case Greeting packet body 为 74B，packet header 后 frame 从 Ethernet/IP/TCP 的 payload offset 54 可见。

### 5.2 Handshake Response（up）

顺序：capability(4 LE)、max_packet_size(4 LE)、charset(1)、reserved(23)、username NUL、auth response（lenenc bytes）、可选 database NUL（CONNECT_WITH_DB）、可选 plugin NUL。默认 capability 为 `0x0008a005`，默认 max packet 为 `0x01000000`。认证算法：native password 为 SHA1 组合；caching_sha2/sha256 的真实 RSA 加密不实现，当前为占位边界。

### 5.3 Auth OK

body 为 `0x00` + affected_rows lenenc + last_insert_id lenenc + status_flags LE + warnings LE；默认 7B，sequence=2。

## 6. Commands、回复与字段布局

`MySQLCommand` 字段完整定义在 `internal/core/types.go:5972–6094`。request body 为 `opcode(1)+Body`，Body 默认 text，也可 hex/base64。允许 opcode 0x01–0x20；典型值：COM_QUERY 0x03、COM_INIT_DB 0x02、COM_PING 0x0e、COM_STMT_PREPARE 0x16、COM_STMT_EXECUTE 0x17、COM_STMT_CLOSE 0x19。

回复模式：`ok`（marker 0x00，默认 autocommit）、`ok-insert`（1/42）、`ok-custom`；`err`（1064/HY000）、`err-perm`（1044/42000）、`err-custom`（marker 0xff + code 2 LE + '#' + 5B SQL state + UTF-8 message）；`result-set`（column_count → column definitions → EOF → rows → EOF）；`binary-result`（binary row marker 0x00 + null bitmap offset 2 + typed LE values）；`prepare-ok`（stmt id 4 LE、num columns/params、warnings/status + defs/EOF）；`no-reply`；`raw`（ReplyBytes 按 MaxPacketSize 切包）。实现位置 planner.go:774–872、987–1315、1319–1447。

Column definition 使用 lenenc strings catalog/schema/table/org_table/name/org_name，再固定 `0x0c` length-of-fixed-fields、charset(2 LE)、column length(4 LE)、type(1)、flags(2 LE)、decimals(1)、2B filler。文本 row 每列为 lenenc string，NULL 为 0xfb。binary row NULL bitmap 为 `ceil((column_count+2)/8)`，类型值按 MySQL enum_field_types 写入。

## 7. 性能、容量与边界

- TCP MSS 合法下限 536（RFC 879 历史 floor），默认 1460；小于 536 被 validator 拒绝。
- MySQL packet length 允许 0..0xFFFFFF；超过上限被拒绝。`raw` reply 按 MaxPacketSize 切分，再按 MSS 做 TCP 分段。
- 最大结果行/列/文本长度受 3B length、MaxPacketSize、内存和 TCP 分段共同限制；代码未为多-result-set 做自动语义解码，需 raw。
- IPv4 与 IPv6 均由 IP 层表示；TCP 头、以太网头和 IPv6 扩展头开销不由 MySQL packet length 计入。

## 8. 验证与错误契约

`Planner.Validate` 只读、不填默认值：IP 非法 → `SrcIP`/`DstIP`；MSS 过小 → `MSS ... too small`；CharacterSet 超界 → `CharacterSet ... out of range`；AuthPlugin 非三种 → `AuthPlugin ... not recognized`；scramble 非 20B → `Scramble length ... invalid`；MaxPacketSize > 0xFFFFFF → `MaxPacketSize ... exceeds`；opcode/BodyEncoding/ReplyEncoding/ReplyMode 非法分别含对应字段；COM_STMT_EXECUTE 的 StmtID=0 → `StmtID == 0`。错误必须传播为任务失败；不可产生成功 PCAP。当前 cases 没有负例，见 G-MYSQL-1。

## 9. 传输、载体与输出

mysql generator 是 TCP terminal layer。layer_gen.go:33–84 通过 `EmitMsg` 发出 Greeting/auth/commands；validator 强制 `spec.TCP.Handshake=true` 与 `Termination=true`（layer_gen.go:123–132），TCP 层负责序号、MSS、握手、挥手。`EmitMsg=nil` 与直接 `EmitEvent` 均返回 wiring error。pcap 和 `port_group`/NIC 是同一生成契约的两种输出，不能为 NIC 单独改变字段或包序。

TLS 不在此层实现；`sha256_password` 的真实 RSA 和 TLS 加密均是待实现边界。

## 10. 已迁移：层链形状与迁移记录

`cases/mysql.json` 的唯一条目 `mysql-basic-session` 已经收敛为层链 `layers=[ip,tcp,mysql]`；地址、端口和终端声明均不再使用顶层 flat 键。本章为迁移记录；§11 的 G-MYSQL-1/2/4/5 为后续覆盖与实现缺口，不涉及迁移残留。

## 11. 缺口登记

| ID | 现象 | 证据 | 归属阶段 |
|---|---|---|---|
| G-MYSQL-1 | cases 只有 1 个正向冒烟，没有 validator/planner/线格式/状态/默认非默认端口/IPv6/截断等负例 | `cases/mysql.json` 仅 `mysql-basic-session`；§8 错误分支未被断言 | P4 用例覆盖 |
| G-MYSQL-2 | MySQL 业务字段和四元组未接入 fixed/inc/rand/list/pattern 五策略 | strategy_convert.go:4628–4660 读标量；无 MySQL 动态序号算法 | P2/P3 动态字段 |
| G-MYSQL-3 | ~~存量 case 仍是 flat spec_json~~（已关闭：cases/mysql.json 已采用 `layers[ip,tcp,mysql]`） | 当前正例无顶层旧键 | 已完成（原 P4 层链迁移） |
| G-MYSQL-4 | 真实 RSA/TLS、multi-result、部分命令能力未实现 | planner.go:45–54 明示 limitation；§5.2 | P3 协议能力 |
| G-MYSQL-5 | tracked `trafficgen/docs/protocol-pcap-test/mysql.md` 过期 | 过期产物仍在旧文档路径 | P4 产物清理 |

## 13. 修订记录

- 2026-10-01：按 HEAD 实现与 cases 逆向整理；登记负例、动态字段、RSA/TLS 与过期产物边界；确认唯一 case 为层链形。

## 14. 层链迁移契约（D1-D8，2026-09-30）

| ID | 结论 | 证据/去向 |
|---|---|---|
| D1 | 地址只住 `layers[].ip`；端口只住 `layers[].tcp`；数量只住独立 `flow_control` | 唯一 case 机读审计；正例无顶层地址、端口、count |
| D2 | MySQL 是依赖 TCP 的终结层，标准链固定为 `[ip,tcp,mysql]` | registry/`planner.go`；case 层顺序一致 |
| D3 | TCP 握手、MSS、序号和挥手由 tcp 层负责，MySQL 只产应用事件 | `layer_gen.go:33-84`、`123-132`；§9 |
| D4 | Greeting、认证、commands/replies 等业务字段只住 `layers[].mysql` | `parseMySQLConfig` 与 `planner.go:528-1447` |
| D5 | 顶层 `mysql` 子映射不得作为正例配置入口；当前无 presence 负例，新增时应单独登记判死形状 | `mysql-basic-session` 无顶层业务键；G-MYSQL-1 |
| D6 | `flow_control` 是策略数量/速率边界，不是 MySQL 业务字段 | §1、CORE_MEMORY §2；当前 case 未显式配置数量 |
| D7 | 当前唯一正例保持原有字段、帧 hex 和最小包数；迁移不重算机器断言 | testcase §2 与 JSON 逐值对账 |
| D8 | 负例、五策略动态、RSA/TLS 与多结果等未实现能力仅登记缺口，不伪造覆盖 | G-MYSQL-1/2/4/5 |

### 15.1 迁移状态与缺口

已迁移 1/1 条 case；正例为 `[ip,tcp,mysql]` 严格层链，顶层旧键零残留。G-MYSQL-1/2/4/5 继续由后续代码/测试阶段处理；本批不改 Go、不宣称 suite 或 NIC 已复跑。

## 15. 修订记录

- 2026-10-01：按 D1-D8 复核层链、case 字段/帧断言与缺口口径；同步修正登录包 notes 的 max_packet 与 root 偏移；仅改设计、测试契约与 cases 三文件。

## 16. 自审结论

自审两轮：第一轮逐项核对 D1-D8、层归属、旧键去向与缺口；第二轮复核唯一 case 的 ID、层顺序及 §1/§10/§11 口径，末轮干净。
