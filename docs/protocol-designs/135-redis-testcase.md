# #135 Redis 用例契约

> 版本：v1.0（2026-09-29）。cases JSON 是机器权威；本文件只记录当前可执行存量与覆盖缺口。pcap/NIC 共用同一契约。

## 1. 测试原则与形状

正例断言必须观察 TCP 方向、长度和 RESP 原始字节；RESP 无 tshark Redis dissector 时不臆造 redis 字段，使用 `tcp.len` 与 payload offset。负例只使用 `expect_error` 与 `error_contains`。统一层形状应为顶层仅 `layers`，但当前 Redis 存量仍为旧平面输入，登记 G-REDIS-1。

## 2. 原子用例索引

| ID | 场景 | 依据链 | 包数 | 断言 |
|---|---|---|---:|---|
| `redis_ping_select_pong` | TCP 6379；默认 SelectDB=0；SELECT 0 后 PING/PONG | RESP array/bulk、simple string；`cases/redis.json:3-75` | min 8（实测 11） | negotiated=true；terminates=true；pkt1 `tcp.dstport=6379`；pkt4 `tcp.len=23`；pkt5 `5`；pkt6 `14`；pkt7 `7`；payload offset 54 的四段 hex 与 JSON 完全一致 |

JSON 的 `expect.min_packets=8` 是下限，不是精确包数；实际结果表报告 11 包。四个 frame 断言分别是 SELECT 请求、+OK、PING 请求、+PONG。

## 3. 三源对账

- ID 集合：design §8/§10 与 JSON 均只有 `redis_ping_select_pong`。
- 场景：JSON 摘要中的“handshake + 4 data frames + FIN”对应 3 TCP 握手 + 4 业务数据 + 4 FIN，共 11；文档不能把摘要的“8”解读为精确总数。
- 断言：字段和 offset 54、hex 均逐字对应 `cases/redis.json:19-75`。
- 观察边界：tshark 3.6 无 Redis-over-TCP dissector，故用原始 payload 和 `tcp.len`，不写不可观察的 `redis.*` 字段。

## 4. 覆盖审计与待扩展行为

当前 case 只直接证明默认/SelectDB+PING/PONG 单流 IPv4 基线。实现测试已覆盖但 cases 未落地的原子行为包括：RESP2/RESP3 HELLO/AUTH、SkipHello、SelectDB -1/15/16 拒绝、ClientName、MULTI/EXEC/DISCARD、订阅与 PSUBSCRIBE 确认、PUBLISH、pipeline ordering、RESP2/3 null/bool/double/map/set/push/attribute、base64/CRLF/空值、int64 边界、MSS 分段、RST/FIN、IPv6、并发 flow、ctx cancellation 和各 validator 错误。它们不计入当前 JSON 已覆盖数。

## 5. 五层反查

| 层 | 当前证据 | 缺口 |
|---|---|---|
| 功能 | PING、SELECT、PONG 四帧原始 bytes | G-REDIS-3：其余命令/RESP 类型/错误分支未入 cases |
| 性能 | 11 包连接、tcp.len 业务段 | G-REDIS-3：MSS、长值、并发 |
| 数据 | ASCII RESP 长度与 CRLF | G-REDIS-3：binary、边界、RESP3 |
| 地址与流 | TCP 6379 单流 IPv4 | IPv6/多 flow 未入 case |
| 业务 | SELECT→PING 请求响应次序 | auth、订阅、pipeline、多事务未入 case |

## 6. 负例契约

当前 JSON 没有负例。已实现 validator 锚词必须后续各有纯负例：invalid IP、MSS too small、invalid Version、SelectDB out of range、negative PipelineSize、empty Args、missing Reply/AutoReply、invalid RESP prefix/length/CRLF、invalid publish message_b64。任务应失败并产 0 包，不能改成跳过。

## 7. 存量逐条去向

| ID | 去向 | 原因 |
|---|---|---|
| `redis_ping_select_pong` | 保留，P4 重钉建议 | 唯一 JSON ID；业务 bytes 有可执行证据，但顶层形状、summary/min_packets 与统一链实际需要复核 |

## 8. 缺口登记

| ID | 现象 | 证据 | 归属 |
|---|---|---|---|
| G-REDIS-1 | JSON 仍为 `count`+`redis` 平面形，summary/min_packets 未精确表达 11 包 | `cases/redis.json:3-24` | P4 契约重钉 |
| G-REDIS-2 | 业务动态字段无五策略/序号断言 | `strategy_convert.go:5179-5240` | P3 动态 |
| G-REDIS-3 | 仅 1 个冒烟 ID，未覆盖实现行为面 | cases 与 `internal/protocol/redis/*test.go` 对账 | P3 用例扩展 |
| G-REDIS-4 | 结果文档早于判死提交且 pcap 目录缺失 | `trafficgen/docs/protocol-pcap-test/redis.md`, git log | P4 结果重跑 |

## 9. 覆盖反查门建议断言行

供主线程登记 `coverage_gate.py`，本车道不修改 gate：

1. `redis_ping_select_pong`：断言 ID 唯一、`min_packets>=8`、`negotiated=true`、`terminates=true`。
2. 同一 ID：逐项检查 packet 1/4/5/6/7 的 `tcp.dstport/tcp.len` 值。
3. 同一 ID：逐项检查四个 offset 54 payload hex，禁止只断言“有 payload”。
4. `cases/redis.json` 顶层形状守卫：标红当前非纯 `layers`。
5. cases 缺少负例、IPv6、MSS、订阅、pipeline、RESP3 的覆盖项，按 G-REDIS-3 标红。
6. 结果产物 `redis.md` 的提交日期 `<0417be5` 或 pcap 目录不存在，按 G-REDIS-4 标红；不得申报今日已过。

## 10. 结果产物核验

`trafficgen/docs/protocol-pcap-test/redis.md` tracked，末次提交 `e7e7d1c`（2026-08-27），早于 `0417be5`（2026-09-13）；对应 `trafficgen/docs/protocol-pcap-test/redis/` 不存在。旧表中的 1 pass/11 packets 只能作为历史记录，不能作为今日复跑证据。

## 11. 修订记录

- v1.0（2026-09-29）：按 Redis JSON、planner/layer_gen、registry、strategy converter 和 Go tests 建立 as-built 用例契约；自审 2 轮，末轮干净。