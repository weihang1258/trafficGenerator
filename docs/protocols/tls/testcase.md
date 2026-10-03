# TLS 1.3 层链测试契约

> 版本：v1.1.0（2026-09-30）
> 机器契约：`trafficgen/test/protocol_pcap/cases/tls.json`（15 例，JSON 顺序权威）。
> 配套设计：`docs/protocols/tls/design.md`；本轮只改文档与 cases 形状，不改实现。
> 证据边界：本文记录现有契约与已登记缺口，不宣称本轮重新运行 suite、PCAP 或 NIC。

## T1 形状、范围与执行边界

15 个唯一语义 ID：9 个正例、6 个负例。正例严格使用 `[ip,tcp,tls,http]`；地址、端口、TLS 参数分别位于对应层，流数位于 case 顶层 `strategy_fc`。非负例 `spec_json` 顶层只有 `layers`。唯一例外 `tls-neg-flat` 故意在层链旁放置 `src_ip`，是验证 flat 配置拒绝的执法靶子，不是残留。

本版测试 TLS 1.3 client 事件变换：TCP 三次握手、7 条 TLS 握手 record、内层 HTTP ApplicationData、TCP FIN。真实密码学、TLS 1.2、server/mTLS、close_notify、IPv6、分片和 RST 不在现有 cases 覆盖范围，均在设计缺口登记。

PCAP 与 NIC 应复用同一 JSON 和断言集合；历史结果或 notes 不等同于本轮执行证据。

## T2 ID、形状与包数

| # | ID | 类型 | 流数 | JSON 包数断言 |
|---:|---|---|---:|---|
| 1 | `tls-handshake-basic` | 正 | 1 | `min_packets=16` |
| 2 | `tls-sni-alpn` | 正 | 1 | `min_packets=16` |
| 3 | `tls-neg-flat` | 负 | 1 | 无 |
| 4 | `tls-neg-static-copy` | 负 | 2 | 无 |
| 5 | `tls-dyn-sni-list` | 正 | 2 | `min_packets=32` |
| 6 | `tls-dyn-sni-pattern` | 正 | 2 | `min_packets=32` |
| 7 | `tls-dyn-sni-fixed` | 正 | 1 | `min_packets=16` |
| 8 | `tls-neg-dyn-closed-version` | 负 | 1 | 无 |
| 9 | `tls-http-inner` | 正 | 1 | `min_packets=16` |
| 10 | `tls-cert-static` | 正 | 1 | `min_packets=16` |
| 11 | `tls-cert-dyn-subject` | 正 | 2 | `min_packets=32` |
| 12 | `tls-cert-dyn-san` | 正 | 2 | `min_packets=32` |
| 13 | `tls-cert-neg-dyn-keytype` | 负 | 1 | 无 |
| 14 | `tls-cert-neg-keytype-value` | 负 | 1 | 无 |
| 15 | `tls-cert-neg-bad-date` | 负 | 1 | 无 |

单流公式为 3 TCP + 7 TLS + 2 ApplicationData + 4 FIN = 16；多流目标为 32。现有正例统一使用 `min_packets`，不把它误写成精确 `packet_count`。

## T3 正例断言

### 基线与握手

`tls-handshake-basic` 断言 TCP flags/443、7 个握手类型 `1,2,8,11,15,20,20`、ClientHello content type 22、默认 ALPN `h2,http/1.1` 与 EncryptedExtensions 回选 `h2`，并在 offset 59 断言 `GET / HTTP/1.1` 和 `HTTP/1.1 200`。它覆盖完整时间线，但不钉非确定的 DER/record 长度。

`tls-sni-alpn` 断言 SNI `example.com`、ClientHello ALPN `h2,http/1.1`、EncryptedExtensions `h2`。

### 动态 SNI 与内层委托

- `tls-dyn-sni-list`：SNI `distinct_values=["a.com","b.com"]`，2 流。
- `tls-dyn-sni-pattern`：SNI `distinct_values=["host1.com","host2.com"]`，2 流。
- `tls-dyn-sni-fixed`：单流精确断言 `a.com`。
- `tls-http-inner`：握手类型 1，并在 offset 59 断言 `GET /tls-inner`，证明 HTTP 事件由 TLS 包成 ApplicationData；当前 notes 记录实测 record length 62，但 JSON 未将其作为长度断言。

多流值均使用 `distinct_values`，不依赖调度后的固定包号；动态端口 list 与业务值按相同 flow index 对齐。

### 证书

`tls-cert-static` 断言 Certificate type 11 和 `x509ce.dNSName=api.test.local,www.test.local`。`tls-cert-dyn-subject` 断言两个 `x509sat.printableString` distinct 值；`tls-cert-dyn-san` 断言 `x509ce.dNSName` distinct 值 `a.test,b.test`。证书 DER 长度不作断言，因为 G-TLS-1 登记的 ECDSA DER 非确定性尚未修复。

正例共 26 条 fields、3 条 frames；frames 当前均 offset 59。`has_payload` 仅是通用帧长启发式，不能单独证明 content type 23（G-TLS-14）。

## T4 负例与错误传播

每个负例都是单一故障，`expect` 严格只有 `expect_error` 与 `error_contains`，不含成功包断言。错误必须在建任务/验证阶段传播，不得返回成功 PCAP、completed/0 packet 或只有 TCP 外壳。

| ID | 故障输入 | 锚词 |
|---|---|---|
| `tls-neg-flat` | 层链旁的顶层 `src_ip` | `no longer accepts flat config field src_ip` |
| `tls-neg-static-copy` | flows=2 + 静态四元组 | `static four-tuple` |
| `tls-neg-dyn-closed-version` | `tls.version` 动态对象 | `does not support dynamic` |
| `tls-cert-neg-dyn-keytype` | `tls.cert.key_type` 动态对象 | `does not support dynamic` |
| `tls-cert-neg-keytype-value` | `key_type=rsa-2048` | `not supported yet` |
| `tls-cert-neg-bad-date` | `not_before=yesterday` | `invalid RFC3339 timestamp` |

未入例的版本/角色、长度、证书形状、日期顺序、IPv6、默认端口、分片、RST、close_notify 分支只登记为缺口，不冒充覆盖。

## T5 覆盖对账与契约检查

| 检查 | 结论 |
|---|---|
| ID 数量/顺序 | 15，本文与 JSON 一致 |
| 正/负比例 | 9/6 |
| 层链 | 15/15 为 `[ip,tcp,tls,http]`；非负例无游离配置键 |
| 负例形状 | 6/6 严格两键，fields/frames 为 0 |
| 动态字段 | SNI、cert.subject、cert.san 有正例；version、role、alpn、cert.key_type、日期动态有拒绝或登记 |
| offsets | 3 条 frames 断言均为 59；record 头基点为 54 |
| 输出路径 | PCAP/NIC 共用断言；本轮未执行不宣称结果 |
| JSON | 未改动；保留现有 15 例机器契约 |

## T6 缺口与执行计划

优先处理 G-TLS-1（证书 DER 确定性），之后才可安全增加长度断言；再补版本/角色/长度拒绝、IPv6、默认端口、分片/空事件与 RST 等 A′ cases。工具侧另处理 TLS 专用 `has_payload`、单流精确 `packet_count` 和动态字符串端口验证。close_notify 是否实现需另立设计裁定。

本轮 JSON 未修改，因此不运行 JSON 改写验证；若后续修改，至少执行 `python3 -m json.tool trafficgen/test/protocol_pcap/cases/tls.json` 并做 ID/层链/顶层键局部审计。当前应在获得授权后分别复跑 PCAP 与 NIC，且以 raw offset、TLS 字段和错误锚词为验收证据。

本版自审两轮：第一轮逐项核对 T1–T6、15 个 ID、正负 expect 形状、严格层链和负例豁免；第二轮复核包数公式、record offset、动态字段、错误锚词及未运行边界，末轮干净。
