# #131 syslog 测试用例契约

> 版本：v1.1.0（2026-09-30，文档轨）
> 机器契约：`trafficgen/test/protocol_pcap/cases/syslog.json`
> 依据：RFC 5424、RFC 3164、RFC 5426；设计契约 D1–D8。

## T1 形状与执行边界

当前 JSON 只有 1 个正例、0 个负例，按数组顺序为权威。配置使用严格层链：地址进 `ip`，端口进 `udp`，syslog 业务字段进 `syslog`；顶层不得出现协议业务键、地址、端口或顶层 `count`。本例为空业务配置，故无顶层业务残留；显式业务字段迁移仍是 G-SYSLOG-1，不能把空配置例外扩大为字段面已收敛。

本轮只验证 JSON 机读形状与存量断言契约，不宣称套件今日复跑。未知层/未接线行为不能计作 syslog 通过。

## T2 原子 ID 与包数

| # | ID | 类型 | 包数 |
|---:|---|---|---:|
| 1 | `syslog_smoke_01` | 正 | 1 |

单流 UDP 包数公式（legacy 业务配置语义）：`messages` 为空或恰有一项时为该单消息的 `count` 复制次数（缺省 1）；`messages` 多于一项时为 `len(messages)` 且忽略 `count`（对应 `planner.go:402-423`、`emitUDP:573-583`）。严格层链的策略流数量另走 `flow_control.flows`；当前 JSON 空 syslog 配置生成一条默认消息，因此为 1 包。UDP 无握手、挥手、RST 或 keepalive；TCP/TLS 待 G-SYSLOG-3 接线后另立用例。

## T3 正例断言

`syslog_smoke_01` 使用 `[udp,syslog]` 最小层链，目标形迁移完成后应展开为严格层内配置。断言：

- `packet_count=1`。
- `udp.dstport=514`。
- `syslog.facility=1`、`syslog.level=6`，对应 PRI `<14>`。
- `syslog.msg="1 - - - - - -"`（tshark 3.6.14 对该存量报文的字段口径）。
- offset 42 的完整 payload hex 为 `3c 31 34 3e 31 20 2d 20 2d 20 2d 20 2d 20 2d 20 2d`。

offset 42 = Ethernet 14 + IPv4 20 + UDP 8。动态 IPv4 ID/校验和不纳入 raw 断言。NIC 与 PCAP 应复用同一字段/raw 断言；当前只有 PCAP 侧证据。

## T4 负例与错误传播

当前 0 个负例，以下必须作为 A′ 原子用例补齐，且每个负例 `expect` 严格只含 `expect_error`、`error_contains`：

| 计划 ID | 输入故障 | 锚词/边界 |
|---|---|---|
| `syslog_neg_facility_overflow` | facility>23 | `Facility` |
| `syslog_neg_severity_overflow` | severity>7 | `Severity` |
| `syslog_neg_format_unknown` | 非法 format | `Format` |
| `syslog_neg_version0_rfc5424` | rfc5424 version=0 | `Version 0 unsupported` |
| `syslog_neg_transport_tcp` | 层链 transport=tcp | `not supported by the layer chain yet` |
| `syslog_neg_timestamp_invalid` | 非 RFC3339 timestamp | `not a valid RFC 3339 timestamp` |
| `syslog_neg_field_too_long` | 字段超长 | `exceeds` |
| `syslog_neg_sd_unclosed` | SD 未闭合 | `unclosed SD-ELEMENT` |
| `syslog_neg_udp_oversize` | UDP payload >65507 | `encoded message exceeds UDP payload limit` |

错误必须传播为 task error，不得成功生成 PCAP、返回 completed/0 packet 或只输出 UDP。当前没有 presence-negative cases：框架缺少 syslog 通用白名单门，暂不伪造该形状；待 G-SYSLOG-1 完成后再单独建例。

## T5 覆盖与审计

| 审计项 | 当前结论 |
|---|---|
| ID 数量/顺序 | 1，JSON 与本文一致 |
| 正/负比例 | 1/0；负例面是明确缺口 |
| 非负例顶层键 | 当前仅 `{layers}`；无地址、端口、业务字段或顶层 `count` 残留，静态闭环为零 |
| 层链 | `[udp,syslog]` ×1，IP 由引擎补全 |
| 正例断言 | 4 条字段 + 1 条完整 payload raw 断言 |
| 负例断言 | 0；按 T4 A′ 补齐 |
| JSON 解析 | `python3 -m json.tool trafficgen/test/protocol_pcap/cases/syslog.json` |

## T6 缺口和执行计划

代码阶段顺序：先完成 G-SYSLOG-1 框架/层字段裁定并迁移正例；再补 T4 负例；随后补显式 RFC 5424 字段、SD、BSD、BOM、messages/count、IPv6 与 metadata 例；TCP/TLS 只有层链放行及分帧口径确定后才建例。每轮先跑 PCAP，再在授权 NIC 上复验相同断言，最后补性能六项（基线、目标规模、压力、长跑、并发交错、背压）。tracked 结果文档当前不作为今日复跑证据。

## T7 CORE §3.15 覆盖裁定

Syslog 当前只生成无连接 UDP datagram，不存在同连接多轮操作、非正常结束或长保活状态机；三项均明确标记为不适用，并由 `syslog_smoke_01` 的单 datagram、无握手/挥手/keepalive 断言覆盖。TCP/TLS 属 G-SYSLOG-3，接线后另建同连接多轮与异常结束例，不把当前单包复制当作事务编排。


| ID | 结论 |
|---|---|
| C1 | JSON 可解析，1 个 ID 唯一且与本文索引一致。 |
| C2 | 正例层链为 `[udp,syslog]`；负例 0，显式业务字段层内承载待 G-SYSLOG-1 后补。 |
| C3 | cases 无顶层地址、端口、业务字段或 count；非负例顶层残留为零，显式层内字段迁移仍登记 G-SYSLOG-1。 |
| C4 | 当前无负例，也没有 presence-negative cases；计划负例均只允许 `expect_error`、`error_contains`。 |
| C5 | 默认字段、端口、PRI、tshark msg 与 offset 42 raw payload 均有断言；NIC、显式字段、多包、BSD、IPv6 和错误传播待执行。 |
| C6 | 本轮只改 syslog design/testcase/cases，不改 Go、全局索引或其他协议。 |

自审：两轮。第一轮逐项核对 T1–T6、JSON ID/层链/顶层键/正负 expect；第二轮复核 offset 42、默认端口、负例锚词和未运行边界；末轮干净。
