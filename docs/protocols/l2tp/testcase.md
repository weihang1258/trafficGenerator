# #141 l2tp（L2TP）测试用例契约

> 版本：v1.0.0（as-built，文档轨批次二）
> 日期：2026-09-29
> 配套设计：`docs/protocols/l2tp/design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/l2tp.json`

## 1. 形状、原则与输出

当前 JSON 只有 **1 个唯一 ID、1 正例、0 负例**，顺序以 JSON 为权威；其 `spec_json` 仍是历史顶层 `l2tp` 子映射形（见设计 §1、G-L2TP-3），不是本轮擅自改写的目标层链形。registry 仅给 l2tp 登记 UDP 依赖与 `udp.dst_port=1701`，没有 l2tp Fields；`translateTerminalConfig` 也没有 l2tp 终结层解码分支（G-L2TP-8），故不能机械迁移 `scenario` 到层内，cases 保持旧骨架。每个断言对应一个可观察字段或原始字节锚点；该冒烟用例验证完整流程，不能替代缺口登记的原子用例。

pcap 与 NIC 共用本文件同一契约：包数、`udp.dstport`、`l2tp.*`、`l2tp.avp.message_type` 和 `frames` 原始字节均不依赖输出路径变化。tracked 结果文档 `trafficgen/docs/protocol-pcap-test/l2tp.md` 早于 0417be5 且未在本轮复跑，不能作为今日通过证据。

## 1.1 D/T/C 三方契约与严格层链裁定

**D（design）**规定最终配置只通过 `layers[].udp` 与 `layers[].l2tp` 承载；**T（testcase）**按同一目标形状描述当前可执行冒烟、缺口和失败契约；**C（cases）**当前唯一权威文件仍为 `trafficgen/test/protocol_pcap/cases/l2tp.json`，统计为 1 个正例、8 包、17 条字段断言和 1 条原始帧断言。

C 的 `spec_json` 实际仍为历史顶层 `l2tp` 子映射，与 D/T 的严格层链目标不一致，登记 G-L2TP-3。当前 `translateTerminalConfig` 没有 `case "l2tp"`，层内 `scenario` 尚不能形成 `spec.L2TP`；若现在改 C 为纯层链，`scenario` 会丢失，不能执行。因此本车道不改 C、不伪造负例；补齐代码接线后再迁移并重新核对 D/T/C 的 ID、包数、fields、frames 和 pcap/NIC 双路径。



|#|ID|场景|依据链|包数|机器断言|
|---:|---|---|---|---:|---|
|1|`l2tp_smoke_01`|L2TPv2 `tunnel_with_data`：SCCRQ/SCCRP/SCCCN + ICRQ/ICRP/ICCN + 一个 PPP IPv4 数据帧 + StopCCN；默认 UDP 目的端口|RFC 2661 §3.1、§4.1、§4.3、§4.4；RFC 1661 §6；设计 §2.1–§3.2|8|包数 8；首包 dstport 1701、type=1、version=2、tunnel=1、session=0、Ns=0、Message Type=1；第2 Nr=1；第3 Ns=1；第8 type=1、Ns=4；Message Type 顺序 1/2/3/9/10/11/4；第7 offset 42 原始 PPP 锚字节|

## 2. 原子测试点与逐项断言

|测试点|用例/缺口|证据|
|---|---|---|
|T-L2TP-01 v2 建隧道三步（SCCRQ/SCCRP/SCCCN）|`l2tp_smoke_01` 第 1–3 包；Message Type `1→2→3`|RFC 2661 §4.1/§4.3；见 2.1|
|T-L2TP-02 v2 建会话三步（ICRQ/ICRP/ICCN）|`l2tp_smoke_01` 第 4–6 包；Message Type `9→10→11`|RFC 2661 §4.3|
|T-L2TP-03 PPP IPv4 数据帧（`ff03/0021`）|`l2tp_smoke_01` 第 7 包帧锚点|RFC 1661 §6|
|T-L2TP-04 StopCCN|第 8 包（Message Type=4）|RFC 2661 §4.4|
|T-L2TP-05 Ns/Nr 关键步|第 1 包 Ns=0、第 2 包 Nr=1、第 3 包 Ns=1、第 8 包 Ns=4|当前抽查口径；全部序号登记，不承诺为契约|
|T-L2TP-06 默认 UDP 目的端口|首包 `udp.dstport=1701`|RFC 2661；`chain_planner.go:1097-1101`|
|T-L2TP-07 HELLO/OCR/OCN/CDN/WEN/SLI/ZLB/LNS/v3|无用例|G-L2TP-4|
|T-L2TP-08 边界值（AVP 1023 上界、DataFrames>1）|无用例|G-L2TP-6/G-L2TP-7|
|T-L2TP-09 异常输入/非法场景|无用例|G-L2TP-4（见 §4 负例表）|
|T-L2TP-10 枚举组合/动态组合/正交组合|未覆盖|G-L2TP-2/G-L2TP-4|
|T-L2TP-11 多事务、多会话、异常终止、长保活|未覆盖；`HelloInterval` 不是已验证的保活语义|G-L2TP-4/G-L2TP-6|

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
|性能|8 包完整流程；单数据帧；控制 AVP 与数据消息均有实际输出|吞吐/并发/资源/长时/背压阈值与测量（G-L2TP-6）；AVP 1023B 上界、相邻值、DataFrames>1；长 inner payload 下内层 IPv4 Total Length、内层 UDP Length、外层承载 UDP Length 的 65535/65536 边界（G-L2TP-7）；G-L2TP-4|
|数据|v2/version、Tunnel/Session、Ns/Nr、Message Type、PPP `ff03/0021`、默认 inner IPv4|AVP M/H/vendor/value、非默认 IDs、InitialNs、结果码、v3 Cookie、inner TCP/ICMP/UDP payload；G-L2TP-4|
|地址与流|单流 IPv4 外层及内层 IPv4；外层 UDP 默认 1701|IPv6 外层（实现支持同族 IP 但 inner 仅 IPv4）、异族拒绝；协议适用但当前未实现/未覆盖多会话的独立状态、生命周期和调度；G-L2TP-6|
|业务|典型 LAC tunnel lifecycle + PPP data + StopCCN|HELLO 保活、重试/重连、呼叫/拆呼、异常终止；UDP 无 FIN/RST；G-L2TP-4|

协议无独立控制流派生数据流：PPP 数据在同一 L2TP tunnel/session 内，因此流关联层按设计 §5 明确“不适用”，不是漏测。

## 3.1 三来源回指

|来源|设计章节|用例/缺口|
|---|---|---|
|RFC 2661 §3.1/§4.1/§4.3（v2 控制）|§2.1–§2.3、§3.2–§3.3|已由 `l2tp_smoke_01` 覆盖|
|RFC 1661 §6（PPP）|§2.3|第 7 包 `ff 03 00 21` 覆盖|
|RFC 3931（v3）|§2.2|无用例，G-L2TP-4|
|商业现网行为|缺失|未取证，G-L2TP-4（不得宣称现网覆盖）|
|本仓库 Planner/layer_gen|§0、§4.3|行为权威，唯一烟例与其一致|
|可靠外部开源实现|未锁定版本证据|只写本仓行为，不冒充第三方验证|

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
|`l2tp_length_boundary_neg`|分别构造长 inner payload，独立覆盖内层 IPv4 Total Length/内层 UDP Length 的 65535 与 65536，以及外层 IPv4 UDP Length 的 65515/65516；另覆盖外层 IPv6/纯 UDP 字段上限 65535/65536|内层两个字段的 65535 仅在封装关系允许时有效；外层 IPv4 UDP Length=65515 允许、65516 必须拒绝；外层 IPv6/纯 UDP Length=65535 允许、65536 必须拒绝；所有超限均须明确 validation/emit error，禁止 uint16 回绕/截断|设计 §2.4；G-L2TP-7；当前 Validate 未实现，代码与用例均待补|

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
|G-L2TP-6|多会话状态/生命周期/调度及性能验收指标未落地|当前仅单组 session/PPPFrames；无吞吐、并发、资源、长时、背压断言|P3/P4 实现与验收|
|G-L2TP-7|内层 IPv4 Total Length、内层 UDP Length 与外层承载 UDP Length 三个独立字段的 65535 允许/65536 拒绝边界无机器断言|本文件 §3 性能行、§4 `l2tp_length_boundary_neg`；设计 §2.4 分层公式|P4 边界与错误传播|
|G-L2TP-8|`layers[].l2tp` 尚未翻译为 `spec.L2TP`，纯层链迁移会丢失 `scenario`|`strategy_convert.go`/`translateTerminalConfig` 缺少 l2tp 终结层分支|P4 层接线后迁移|

## 7. 门建议断言行

供主线程 `coverage_gate.py` 登记，以下均为静态可机读目标：

1. ID 集合精确为 `[l2tp_smoke_01]`，顺序一致。
2. `l2tp_smoke_01.expect.packet_count == 8`。
3. `fields` 含上述 17 个字段断言，覆盖 7 个 Message Type 断言及控制/数据头关键字段。
4. `frames` 含 `packet=7, offset=42, hex=00 01 00 00 ff 03 00 21`。
5. 负例集合当前为空；未来负例必须是纯 `expect_error,error_contains`。
6. design §1 目标 spec 形与 cases 当前形差异必须显式报告 G-L2TP-3，不得把存在旧键误判为通过。
7. 五层覆盖表中未覆盖项不得申报已覆盖；G-L2TP-1 不得以 tracked 结果文档替代复跑证据。

## 8. 自审与修订

- 2026-09-29 初稿：从 `cases/l2tp.json` 逐字段转录，并回指 planner/layer_gen/types。
- 2026-10-01：核对 registry、strategy_convert、`translateTerminalConfig` 与 chain planner；确认 registry 无 l2tp Fields 且终结层无 l2tp 解码分支；更新 D/T/C 阻塞事实，当前唯一存量 JSON 不迁移，不伪造迁移。
- 自审 2 轮，末轮干净：第 1 轮核对 1 ID、8 包、17 个 field 项、1 个 frame 锚点与 JSON；第 2 轮核对 Message Type 顺序、offset、缺口三要素和负例纯净性，确认未改代码/cases。独立覆盖对抗审查仍待主线程安排。

## 9. T1–T6 测试静态闭环

| ID | 必核对项 | 结论 |
|---|---|---|
| T1 | 测试点清单和三源回指 | `l2tp_smoke_01` 覆盖 v2 建隧道、建会话、PPP 数据、StopCCN；其余规范面逐项保留 G-L2TP-4。|
| T2 | 原子粒度、场景与强度 | 当前唯一例是集成冒烟，不冒充原子全集；多会话/多事务/异常/长保活及性能六场景均登记缺口。|
| T3 | §3.15 会话、事务、关联 | 单 tunnel/session、单控制流内 PPP 载荷，无独立子流；多会话生命周期和调度未实现，G-L2TP-6。|
| T4 | 存量 ID 去向 | 唯一 ID `l2tp_smoke_01` 原样保留；无新增未来能力 ID，无删除断言。|
| T5 | 负例失败路径 | 当前无负例；规划表中的缺配置、未知 scenario、冲突、AVP 超长、坏 IP、坏 inner、坏 cookie、PPP=0 均有真实 planner 锚词，补入前不计覆盖。|
| T6 | JSON 与设计对账 | 1 ID、8 包、17 条 fields、1 条 frame 与 design §1.1/§2.1 和 JSON 一致；当前顶层旧键按 G-L2TP-3/G-L2TP-8 如实登记。|

## 10. C1–C6 六项静态闭环清单

| ID | 核对项 | 结论 |
|---|---|---|
| C1 | JSON 解析、ID 集合与正负数量 | 1/1 唯一；1 正、0 负；顺序与本文 §2 及 design 对齐。|
| C2 | 严格层链形状 | 当前仍是 legacy 形：`spec_json` 有顶层 `l2tp`，没有可执行的层内业务配置；迁移阻塞 G-L2TP-3。registry 没有 l2tp Fields、translate 也没有终结层解码分支，见 G-L2TP-8。|
| C3 | 地址/端口/业务归属 | 目标业务在 `layers[].l2tp`、端口在 `layers[].udp`；当前 `scenario` 仍在顶层且 cases 保持旧骨架，见 G-L2TP-3/G-L2TP-8。|
| C4 | 正负 expect 纯净性 | 正例字段/帧断言可观察；负例为空。未来负例 expect 严格双键 `expect_error`/`error_contains`，锚词取真实 validator 文案。|
| C5 | 行为面覆盖与缺口 | v2 主路径已覆盖；其余控制消息、ZLB、v3、边界、地址族、内层变体、动态和错误分支均列缺口，不把文档规划写入 JSON。|
| C6 | 双输出与接线边界 | pcap/NIC 约定共用同一 JSON；registry/layer_gen 有注册，但 translate 缺口未闭合；本轮不跑 suite/MCP/NIC/服务器/Go。|

以上为静态闭环，不表示真实 pcap、NIC、suite 或任务失败终态已验收。
