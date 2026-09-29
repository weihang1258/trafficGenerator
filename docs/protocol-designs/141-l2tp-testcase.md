# #141 l2tp（L2TP）测试用例契约

> 版本：v1.0.0（as-built，文档轨批次二）
> 日期：2026-09-29
> 配套设计：`141-l2tp-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/l2tp.json`

## 1. 形状、原则与输出

当前 JSON 只有 **1 个唯一 ID、1 正例、0 负例**，顺序以 JSON 为权威；其 `spec_json` 仍为旧的顶层 `l2tp` 子映射形（见设计 §8 §1、G-L2TP-3），不是本轮擅自改写的目标层链形。每个断言对应一个可观察字段或原始字节锚点；该冒烟用例验证完整流程，不能替代缺口登记的原子用例。

pcap 与 NIC 共用本文件同一契约：包数、`udp.dstport`、`l2tp.*`、`l2tp.avp.message_type` 和 `frames` 原始字节均不依赖输出路径变化。tracked 结果文档 `trafficgen/docs/protocol-pcap-test/l2tp.md` 早于 0417be5 且未在本轮复跑，不能作为今日通过证据。

## 2. 用例索引（与 JSON 逐条一致）

|#|ID|场景|依据链|包数|机器断言|
|---:|---|---|---|---:|---|
|1|`l2tp_smoke_01`|L2TPv2 `tunnel_with_data`：SCCRQ/SCCRP/SCCCN + ICRQ/ICRP/ICCN + 一个 PPP IPv4 数据帧 + StopCCN；默认 UDP 目的端口|RFC 2661 §3.1、§4.1、§4.3、§4.4；RFC 1661 §6；设计 §2.1–§3.2|8|包数 8；首包 dstport 1701、type=1、version=2、tunnel=1、session=0、Ns=0、Message Type=1；第2 Nr=1；第3 Ns=1；第8 type=1、Ns=4；Message Type 顺序 1/2/3/9/10/11/4；第7 offset 42 原始 PPP 锚字节|

### 2.1 `l2tp_smoke_01` 逐项断言

`spec_json`：`{"l2tp":{"scenario":"tunnel_with_data"}}`。期望 `packet_count=8`。

- 第 1 包：`udp.dstport = 1701`；`l2tp.type = 1`（控制 T 位）；`l2tp.version = 2`；`l2tp.tunnel = 1`；`l2tp.session = 0`；`l2tp.Ns = 0`；`l2tp.avp.message_type = 1`（SCCRQ）。
- 第 2 包：`l2tp.Nr = 1`；`l2tp.avp.message_type = 2`（SCCRP）。
- 第 3 包：`l2tp.Ns = 1`；`l2tp.avp.message_type = 3`（SCCCN）。
- 第 4 包：`l2tp.avp.message_type = 9`（ICRQ）。
- 第 5 包：`l2tp.avp.message_type = 10`（ICRP）。
- 第 6 包：`l2tp.avp.message_type = 11`（ICCN）。
- 第 7 包：`offset=42`，hex `00 01 00 00 ff 03 00 21`。该锚点同时观察 v2 数据 TunID=1、SesID=0、PPP HDLC `ff03` 和 PPP IPv4 Protocol `0021`；数据消息 T=0 的 type 不依赖 tshark 字段，而由首比特字节锚点覆盖。
- 第 8 包：`l2tp.type = 1`；`l2tp.Ns = 4`；`l2tp.avp.message_type = 4`（StopCCN）。

序列断言不是“有这些消息即可”：Message Type AVP 的包序必须严格为 `1 → 2 → 3 → 9 → 10 → 11 → (data) → 4`。Ns/Nr 只抽查关键步，避免把实现探针中未承诺的所有数值误当契约。

## 3. 五层覆盖反查

|层|已覆盖的不可再分点|未覆盖/缺口|
|---|---|---|
|功能|完整 v2 建隧道、建会话、数据、StopCCN；7 个控制 Message Type 顺序；控制/数据 T 位|其余 HELLO/OCRQ/OCRP/OCCN/CDN/WEN/SLI/ZLB；显式 scenarios；LNS 方向；v3；G-L2TP-4|
|性能|8 包完整流程；单数据帧；控制 AVP 与数据消息均有实际输出|AVP 1023B 上界、相邻值、DataFrames>1、长 inner payload/IPv4 长度上界；G-L2TP-4|
|数据|v2/version、Tunnel/Session、Ns/Nr、Message Type、PPP `ff03/0021`、默认 inner IPv4|AVP M/H/vendor/value、非默认 IDs、InitialNs、结果码、v3 Cookie、inner TCP/ICMP/UDP payload；G-L2TP-4|
|地址与流|单流 IPv4 外层及内层 IPv4；外层 UDP 默认 1701|IPv6 外层（实现支持同族 IP 但 inner 仅 IPv4）、异族拒绝、多流/多会话；G-L2TP-4|
|业务|典型 LAC tunnel lifecycle + PPP data + StopCCN|HELLO 保活、重试/重连、呼叫/拆呼、异常终止；UDP 无 FIN/RST；G-L2TP-4|

协议无独立控制流派生数据流：PPP 数据在同一 L2TP tunnel/session 内，因此流关联层按设计 §5 明确“不适用”，不是漏测。

## 4. 负例和失败传播

当前 JSON 没有 `expect_error`。实现已定义但未有机器证据的负路径必须补独立用例，不能将正例冒充负例：

|建议 ID|输入|应观察锚词|代码证据|
|---|---|---|---|
|`l2tp_missing_config_neg`|`spec.L2TP=nil`|`L2TP config is required`|`planner.go:189-192`|
|`l2tp_unknown_scenario_neg`|未知 Scenario|`Scenario %q unknown`|`:205-210`|
|`l2tp_scenario_conflict_neg`|Scenario 与 Scenarios/PPPFrames 并存|`cannot both be set`|`:195-204`|
|`l2tp_avp_overflow_neg`|AVP 总长 1024|`exceeds max 1023`|`:282-299`|
|`l2tp_bad_ip_neg`|非法或异族 outer IP|`not a valid IP` / `same IP version`|`:156-179`|
|`l2tp_bad_inner_neg`|inner IPv6/非法 proto/负 DataFrames|`must be IPv4` / `not in supported list` / `must be >= 0`|`:302-334`|
|`l2tp_bad_cookie_neg`|v3 Cookie 非 0/4/8/16|`Cookie length`|`:245-252`|
|`l2tp_bad_ppp_protocol_neg`|PPP Protocol=0|`PPPFrames[%d].Protocol 0 invalid`|`:272-276`|

每条负例执行期只保留 `expect_error` 与 `error_contains`；任务必须失败且不得产生成功 PCAP、completed/0 packet 或 TCP/UDP 外壳假成功。上述均为待补，不计入当前 1 条已覆盖统计。

## 5. 存量审计

|现有 ID|去向|原因|
|---|---|---|
|`l2tp_smoke_01`|保留，原顺序与包数/断言逐条照录|唯一已落地机器契约；覆盖集成主路径|

没有其他存量 ID；未新增未来能力 ID。

## 6. 缺口登记

|ID|现象|证据|归属阶段|
|---|---|---|---|
|G-L2TP-1|结果产物陈旧，不能证明本轮套件执行|`trafficgen/docs/protocol-pcap-test/l2tp.md` 最后提交 2026-08-27 < `0417be5`|P4 复跑|
|G-L2TP-2|动态四元组/业务字段策略与 N 流展开无机器覆盖|`strategy_convert.go:1197` 仅解析静态 L2TPConfig|P4 接线|
|G-L2TP-3|唯一 case 仍是顶层 l2tp 子映射，不是目标纯层链|`cases/l2tp.json:6-10`|P4 迁移|
|G-L2TP-4|功能、边界、负例、v3、IPv6、内层变体和业务状态面严重欠覆盖|本文件 §3 五层反查、§4 负例表|P3/P4 覆盖|
|G-L2TP-5|Planner 构造错误在 goroutine 中停止 channel，未形成可观察 error 传播契约|`planner.go:573-576`|P4 错误传播|

## 7. 门建议断言行

供主线程 `coverage_gate.py` 登记，以下均为静态可机读目标：

1. ID 集合精确为 `[l2tp_smoke_01]`，顺序一致。
2. `l2tp_smoke_01.expect.packet_count == 8`。
3. `fields` 含上述 17 个字段断言（含 7 个 Message Type、3 个 type/version/tunnel/session/Ns/Nr 关键断言）。
4. `frames` 含 `packet=7, offset=42, hex=00 01 00 00 ff 03 00 21`。
5. 负例集合当前为空；未来负例必须是纯 `expect_error,error_contains`。
6. design §1 目标 spec 形与 cases 当前形差异必须显式报告 G-L2TP-3，不得把存在旧键误判为通过。
7. 五层覆盖表中未覆盖项不得申报已覆盖；G-L2TP-1 不得以 tracked 结果文档替代复跑证据。

## 8. 自审与修订

- 2026-09-29 初稿：从 `cases/l2tp.json` 逐字段转录，并回指 planner/layer_gen/types。
- 自审 2 轮，末轮干净：第 1 轮核对 1 ID、8 包、17 个 field 项、1 个 frame 锚点与 JSON；第 2 轮核对 Message Type 顺序、offset、缺口三要素和负例纯净性，确认未改代码/cases。独立覆盖对抗审查仍待主线程安排。
