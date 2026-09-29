# #135 Redis（RESP2/RESP3 over TCP）设计契约

> 版本：v1.0（2026-09-29，as-built）；依据：Redis Serialization Protocol 2/3、RFC 9293 TCP；实现与用例优先。
> 范围：`[tcp, redis]` 终结层，默认 TCP 6379；本版描述已落码能力，不把真实 Redis 服务端语义冒充为生成器能力。

## 1. 范围、实现状态与输出契约

Redis 是单 TCP 会话上的 RESP 请求/响应流。`trafficgen/internal/protocol/redis/planner.go` 是 legacy 规划器，`layer_gen.go` 是统一层链事件生成器；registry 已在 `trafficgen/internal/core/layers/registry.go:1576` 注册 `redis`，依赖 `tcp`，默认端口由层契约声明但用户显式端口优先。统一链的 TCP 握手、序列号、MSS 分段和 FIN 由 tcp 层承担；redis 层只发业务事件。pcap 与 NIC 使用同一 `cases/redis.json` 契约。

严格目标形状（当前存量 case 仍是旧平面 spec_json，见 §12.1）：
```json
{"layers":[{"tcp":{"dst_port":6379}},{"redis":{"select_db":0,"commands":[{"args":["PING"],"auto_reply":"pong"}]}}]}
```

配置输入通过 `strategy_convert.go:1289,5179-5240` 转成 `RedisConfig`。当前 layer registry 没有 Redis `Fields` 显式清单；层内翻译须以 `RedisConfig` 字段为准。输出事件顺序为：RESP3 HELLO/AUTH 或 RESP2 AUTH → SELECT → CLIENT SETNAME → SUBSCRIBE/PSUBSCRIBE 与确认 → commands（按 pipeline 分组）→ PUBLISH → TCP termination。

## 2. 线格式与字段规格

### 2.1 RESP 数组请求

每个命令编码为 `*<argc>\r\n`，随后每个参数为 `$<byte_len>\r\n<data>\r\n`；总长度为 `len("*N\r\n") + Σ(len("$L\r\n")+L+2)`，长度按 UTF-8/原始字节计数，不转义 CRLF。`Args` 先写，`ArgsBase64` 逐项标准 base64 解码后追加，若两者为空且 `Channel` 非空则 Channel 成为唯一参数（`planner.go:506-525`）。空参数列表由 validator 拒绝。

### 2.2 RESP 回复

`Reply` 是完整原始 RESP 帧，必须有合法类型前缀 `+ - : $ * _ # , ( ! = % ~ > |` 且以 CRLF 结尾；长度类前缀的首行须为十进制整数（`planner.go:150-203`）。自动回复：`ok`=`+OK`, `queued`=`+QUEUED`, `pong`=`+PONG`, `nil`=`$-1`, `nil-array`=`*-1`, `empty-arr`=`*0`, `integer-n`=`:n`。`EmitAsPush` 把非 `>` 回复包装为 RESP3 `>1\r\n<reply>`。

### 2.3 控制与订阅帧

RESP3 `version=3` 且 `skip_hello=false` 时先发 `HELLO 3`，有凭据时追加 `AUTH [username] password`，回复 `%0\r\n`；RESP2 有 Password 时发 `AUTH [username] password`，回复 `+OK\r\n`。`SelectDB` 在 [-1,15]，>=0 发 `SELECT n`；ClientName 非空发 `CLIENT SETNAME name`。Subscribe 发一个 `SUBSCRIBE c...`，每频道确认 `*3`：kind、channel、`:count`; PSUBSCRIBE 同理。Publish 为 `PUBLISH channel message`，回复 `:1\r\n`；`message_b64` 优先于 message。

### 2.4 TCP 与分段

legacy planner 可独立产生 SYN/SYN-ACK/ACK、数据 PSH-ACK 和 FIN 四包或 RST；统一链强制 validator 将 TCP Handshake/Termination 设为 true（`layer_gen.go:228-243`），不支持 Redis 层 RST 开关。业务 payload 按 `TCP.MSS` 分段，段数 = `ceil(payload_bytes/MSS)`；MSS 小于 536 拒绝。IPv4/IPv6 地址由 IP/TCP 层编码；Redis 不限制地址族。

## 3. 事务与状态机

一次事务是一个 client RESP array 与一个 server reply 的配对；pipeline N>1 是 N 个请求连续发出后按序 N 个回复。自动派生顺序确定，不模拟服务端状态校验（MULTI/EXEC、订阅态命令限制等由用户剧本负责）。状态集合：Start → optional bootstrap → optional select/name/subscription → command batches → publish → Terminating → Done；非法输入在 Validate 或事件生成时返回错误，不产生成功流。上下文取消由 `layer_gen.go:202-212` 传播。

五件套：会话表 = 每个 flow 的四元组/packet index/seq 状态（由 tcp 层统一）；事务序列 = 上述事件顺序；关联关系 = 同一 command 的请求/回复按 list 顺序配对，pipeline 保持批内序；插入位置 = bootstrap 在 commands 前、publish 在 commands 后、TCP 边界由 transport 插入；时间线 = TCP handshake → Redis events → FIN。无控制流派生数据流，流关联不适用；多会话由策略层多个 flow 展开，Redis 单连接本身不交错并发。

## 4. 业务场景与五层覆盖

- 功能：PING/SELECT、RESP2 AUTH、RESP3 HELLO、CLIENT SETNAME、SUBSCRIBE/PSUBSCRIBE、PUBLISH、普通命令、pipeline、FIN/RST；现有 pcap 仅覆盖 PING+SELECT。
- 性能：MSS 跨段、10MB 回复与并发 flow 已由 Go tests 覆盖；RESP 长度受内存与 TCP 分段约束，无固定 Redis payload 上限。
- 数据：文本、空值、CRLF、base64 二进制、RESP2/RESP3 类型、int64 边界、无效前缀/长度/CRLF/空 Args。
- 地址与流：IPv4/IPv6 由共用 transport 支持；单流基线有 pcap；多流/多会话由框架 flow 展开，Redis 无副流关联。
- 业务：认证→选择 DB→命名→命令事务、MULTI/EXEC、订阅发布、pipeline、退出/异常终止均有 planner tests；cases JSON 尚未展开这些行为。

## 5. 动态字段

当前 Redis 业务字段均为静态 `RedisConfig` 值；策略层已具备通用 flow 四元组策略，但 `parseRedisConfig`（`strategy_convert.go:5179`）只读取普通标量/list，不为 Version、SelectDB、PipelineSize、命令参数、Reply、Channel、消息建立 fixed/inc/rand/list/pattern 五策略序号算法。故本版动态业务字段是待实现边界，不计为已覆盖：四元组由通用层按 flow 序号生成；Redis 动态字段需在转换层按流序号确定性映射，并保持 values 只落 redis config。

## 6. 错误处理契约

| 锚词 | 触发 | 结果 |
|---|---|---|
| `SrcIP ... not a valid IP` / `DstIP ...` | 地址非法 | Validate error，零包 |
| `TCP.MSS ... too small` | MSS<536 | Validate error，零包 |
| `Version ... invalid` | 非 0/2/3 | Validate error，零包 |
| `SelectDB ... out of range` | 不在 [-1,15] | Validate error，零包 |
| `PipelineSize ... cannot be negative` | <0 | Validate error，零包 |
| `has no arguments` | command 无 Args/Base64/Channel | Validate error，零包 |
| `has no Reply and no AutoReply` | 无回复来源 | Validate error，零包 |
| `invalid RESP prefix` / `length ... not a valid integer` / `reply must end` | 回复格式错误 | Validate error，零包 |
| `MessageB64` | 发布消息 base64 非法 | Validate error，零包 |
| `EmitMsg is nil` | 层未接 transport | Generate error，空流 |

## 7. 性能与容量

MSS 默认 1460，RFC 879 最小值 536；SYN 选项为 MSS、Window Scale 7、SACK permitted。每个事件一完整 RESP frame，跨 MSS 时事件可能展开成多个 TCP payload 段。pipeline 仅改变请求/回复批次顺序，不改变总 RESP 字节。生成器流式输出，不能依赖聚合全流。

## 8. 存量与差异边界

当前 JSON 只有 `redis_ping_select_pong`：摘要声称 8，但实际 pcap 11 包（3 handshake + 4 data + 4 FIN），`expect.min_packets=8`，字段/frames 仅覆盖业务四帧。代码默认 SelectDB=-1，而该 case 的旧输入缺省解析得到 SelectDB=0，实际 SELECT 0；该差异登记 G-REDIS-1。统一 layer 生成器固定 FIN，legacy 可 RST；两条路径不得混合握手。

## 9. 规范矩阵与建议

RESP2/RESP3 基本帧、数组 bulk 编码和 TCP 载体已实现；真实服务端状态机、TLS、集群、分片和服务端持久化语义不实现。建议后续 cases 按原子行为增补：RESP2/3 bootstrap、auth、select 边界、订阅确认、pipeline、binary、MSS、错误和 IPv6；不修改现有断言以掩盖差异。

## 10. 门1 §1–§14 对照表

| 门 | 本协议满足方式与证据 |
|---|---|
| §1 顶层旧键 | 存量 case 顶层为 `count,redis`，目标迁移到纯 `layers`，字段去向见 §1 样例；代码 `strategy_convert.go:1289`。 |
| §2 规范依据 | RESP2/RESP3 serialization spec、RFC 9293；实现 `planner.go:150-203`。 |
| §3 五件套 | 会话/事务/关联/插入/时间线见 §3；单 TCP 无流关联。 |
| §4 五层 | 功能/性能/数据/地址与流/业务逐层见 §4。 |
| §5 状态机 | Start→bootstrap→transactions→termination，见 §3。 |
| §6 线格式 | RESP 数组/回复/订阅编码与公式见 §2。 |
| §7 错误 | 11 类锚词表见 §6。 |
| §8 动态 | 四元组走通用层；Redis 业务动态待实现，见 §5。 |
| §9 性能 | MSS、分段、pipeline、流式约束见 §7。 |
| §10 测试契约 | cases JSON 为权威，现存 1 ID，详见 testcase。 |
| §11 接线 | registry:1576，layer_gen.go:224，strategy_convert.go:1289。 |
| §12 动态字段 | 清单与序号算法缺口见 §5/§12.12。 |
| §13 输出 | pcap/NIC 共用 cases 与 offset/bytes 断言，见 §1。 |
| §14 缺口 | G-REDIS-1…G-REDIS-4 见 §11。 |

### 12.1 §1 旧键去向与完整目标形状

`count` → `flow_control.flows`；`redis` 子映射 → `layers[].redis`；传输端口 → `layers[].tcp.dst_port`；地址/MAC → `ip`/`tcp` 层；业务字段逐一落 `redis` 层：`version,skip_hello,username,password,select_db,client_name,commands,subscribe_to,subscribe_patterns,publish_messages,pipeline_size`。目标形状：
```json
{"layers":[{"tcp":{"dst_port":6379}},{"redis":{"version":2,"select_db":0,"commands":[{"args":["PING"],"auto_reply":"pong"}]}}],"flow_control":{"flows":1}}
```

### 12.12 §12.12 动态字段清单

| 类别 | 字段 | 当前序号算法 | 状态 |
|---|---|---|---|
| 四元组 | src_ip,dst_ip,src_port,dst_port | 通用 flow index | 已由框架承载 |
| 业务 | version, SelectDB, ClientName, command Args/Reply/Channel, Publish fields | 无 Redis-specific index resolver | G-REDIS-2 |
| 业务 | binary/message, PipelineSize | 无 | G-REDIS-2 |

## 11. 缺口登记表

| ID | 现象 | 证据 | 归属阶段 |
|---|---|---|---|
| G-REDIS-1 | 存量 case 摘要/最小包数与实现实测不一致，且旧平面形 | `cases/redis.json:3-24`；旧结果 `trafficgen/docs/protocol-pcap-test/redis.md` | P4 契约重钉 |
| G-REDIS-2 | Redis 业务字段未接五策略动态值与流序号算法 | `strategy_convert.go:5179-5240` 仅普通标量解析 | P3 动态字段 |
| G-REDIS-3 | cases 仅一个综合冒烟，未覆盖已实现 RESP2/3、错误、MSS、订阅、pipeline、IPv6 行为面 | `cases/redis.json` 与 redis tests 对比 | P3 用例扩展 |
| G-REDIS-4 | tracked 结果产物末次提交 2026-08-27，早于 `0417be5`，且 Redis pcap 目录不存在 | `git log`, `trafficgen/docs/protocol-pcap-test/redis.md` | P4 结果重跑 |

## 12. 修订记录

- v1.0（2026-09-29）：按实现、registry、strategy converter、cases JSON 逆向建立 as-built 文档；自审 2 轮，末轮干净。