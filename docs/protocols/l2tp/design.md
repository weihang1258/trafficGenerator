# #141 L2TP 设计契约

> 版本：v1.0.0（as-built，文档轨批次二）
> 日期：2026-09-29
> 依据：RFC 2661（L2TPv2）§3–§5、§7，RFC 1661 §6，RFC 791 §3.1，RFC 768，RFC 793，RFC 3931 §3、§5；现有 planner/layer_gen/types/registry 与 `cases/l2tp.json`。
> 范围：UDP 承载的 L2TPv2/v3 控制消息和 PPP 数据消息；当前机器契约仅落地 L2TPv2 `tunnel_with_data`。

## 0. As-built 边界

`internal/protocol/l2tp/planner.go` 的 `Planner.Validate` 与 `Plan` 是线格式和默认值权威；`layer_gen.go:35-78` 复放 Planner 的 `PacketConfig` 为 `MessageEvent`，并固定 `L4PortOverride=true`，避免 UDP 层再次交换方向端口。registry `registry.go:507-510` 将 l2tp 注册为 `CategoryTerminal`、依赖 `udp`，且 FieldContract 只有承载层默认 `udp.dst_port=1701`，没有可用于解码业务字段的 l2tp Fields；`strategy_convert.go:1197-1200` 只解析传入配置映射中的顶层 `l2tp` 子映射；`layers/chain_planner_translate.go:756-` 的 `translateTerminalConfig` 没有 `term.Name == "l2tp"` 分支，因此尚未把 `layers[].l2tp` 解码到 `spec.L2TP`。chain planner 在 `chain_planner.go:1097-1101` 缺省目的端口 1701。层内翻译缺口单列 G-L2TP-8。当前 cases 只有 `l2tp_smoke_01`（8 包），其 `spec_json` 仍为历史顶层 `l2tp` 子映射；这只是当前存量输入的 as-built 事实，不是已完成的纯层链迁移。目标契约仍为本节所示纯层链，登记 G-L2TP-3；文档不把未落入 JSON 的能力冒充已覆盖。

## 1. 配置形状、输入与输出

纯层链形（顶层无游离 l2tp 键；这是目标形，当前 case 尚未达到）

```json
{
  "layers": [
    {"udp": {"dst_port": 1701}},
    {"l2tp": {"scenario": "tunnel_with_data"}}
  ]
}
```

层链进入 `FlowSpec` 后应由 `parseL2TPConfig`（`strategy_convert.go:3557`）形成 `spec.L2TP`；但当前 registry/translate 仅声明终结层和 UDP 端口默认，没有 l2tp Fields，也没有 `translateTerminalConfig` 的 `term.Name == "l2tp"` 解码分支（G-L2TP-8），所以仅使用 `layers[].l2tp` 尚不能形成配置，整体迁移登记 G-L2TP-3。

## 1.1 D/T/C 三方契约与严格层链裁定

**D（design）**规定最终配置只通过 `layers[].udp` 与 `layers[].l2tp` 承载，外层地址和端口不游离到顶层；**T（testcase）**按同一目标形状描述当前可执行冒烟、缺口和失败契约；**C（cases）**当前权威文件仍是 `trafficgen/test/protocol_pcap/cases/l2tp.json`，包含 1 个正例 `l2tp_smoke_01`、8 包、17 条字段断言和 1 条原始帧断言。

C 的 `spec_json` 实际仅含历史顶层 `l2tp` 子映射，没有 `layers` 键，和 D/T 的纯层链目标不一致，登记 G-L2TP-3；当前 `translateTerminalConfig` 没有 `term.Name == "l2tp"` 分支，registry 也没有 l2tp Fields，不能把 C 改成仅层链后宣称可执行，因此本车道不改 C、不伪造负例。补齐层内接线后，必须重新核对 D/T/C 的 ID、包数、fields、frames，并同时验证 pcap/NIC。

`L2TPConfig` 字段按 `types.go:5173-5288` 分为：版本/角色（`version` 0→2，`role` lac/lns）、隧道与会话 ID（16 位 v2、32 位 v3）、自动 AVP 参数（hostname、vendor、firmware、framing/bearer、窗口、tie-breaker、protocol version）、序列/端口承载、显式 `scenarios[]`、`ppp_frames[]`、`custom_avps[]`、结果码和内置 `scenario`。`inner_ip` 仅供 `tunnel_with_data` 生成内层 IPv4。

## 2. 线格式

所有多字节线字段均为网络字节序（big-endian），除内层 IPv4/UDP/TCP/ICMP 各自 RFC 规定字段外也同样采用 network order。

### 2.1 L2TPv2 控制报文（RFC 2661 §3.1）

固定头 12B：

|偏移|宽度|字段|实现|
|---:|---:|---|---|
|0|2|Flags/Version|`T=1,L=1,S=1`，低版本位=2，即 `0xC802`|
|2|2|Length|整个 L2TP payload，含头和 AVP|
|4|2|Tunnel ID|有效隧道 ID；默认 local=1|
|6|2|Session ID|隧道级消息必须为 0|
|8|2|Ns|发送序号|
|10|2|Nr|对端下一期望序号|

总长公式：`12 + Σ(6 + len(AVP.Value))`。每个控制消息首先插入 Message Type AVP（M=1、Vendor=0、AttrType=0、值为 2B 消息类型）；ZLB 例外为仅 12B 头、无 AVP。AVP 头 6B：M/H、保留位、10-bit Length（含头，6..1023）、Vendor ID 2B、Attribute Type 2B；不填充、不对齐。

### 2.2 L2TPv3 控制/数据

v3 控制头为 14B：Flags/Version 2B、Length 2B、Tunnel ID 2B、32-bit Session ID 4B、Ns 2B、Nr 2B；数据头为 Flags 1B、Version 1B、32-bit Session ID 4B，后跟可选 4/8/16B Cookie。`Cookie` 长度仅允许 0/4/8/16。当前 JSON 未覆盖 v3；这是已实现但未覆盖边界。

### 2.3 L2TPv2 数据与 PPP

v2 数据头 4B：Tunnel ID 2B + Session ID 2B；后接 PPP 字节。启用 `l2_ppp_header` 时，PPP 为 `ff 03` + Protocol 2B + Information；`tunnel_with_data` 固定 PPP Protocol `0x0021`（IPv4），故数据 payload 公式为 `4 + 2 + 2 + len(inner_ipv4)` = `8 + len(inner_ipv4)`。测试第 7 帧 offset 42 的 `00 01 00 00 ff 03 00 21` 验证 v2 TunID=1、SesID=0、HDLC 与 IPv4 协议。

### 2.4 内层 IPv4

`inner_ip` 仅允许 IPv4。IPv4 头固定 20B、IHL=5、DF、TTL 默认 64、IPID 从 1 按数据帧递增，协议支持 ICMP(1)、TCP(6)、UDP(17)，默认 UDP。UDP 头 8B、checksum=0；TCP 头 20B、窗口 65535、计算伪首部 checksum；ICMP echo request 8B、计算 checksum。长度上界必须分层计算，不能把两个 UDP Length 混为一项：内层 IPv4 `Total Length = 20 + inner_l4_length`，其中内层 UDP 的 `Length = 8 + inner_udp_payload_length`，这两个字段各自是 IPv4/UDP 的 16-bit 无符号长度，字段值上限为 65535。外层承载 UDP 的 `Length = 8 + l2tp_payload_length`，其中 `l2tp_payload_length` 包含 L2TP 头、PPP 头（如启用）和完整内层 IPv4；在外层 IPv4 上，UDP 总长度还受 IPv4 最大无分片报文限制，故有效上限为 **65515**（65535 − IPv4 头 20B），而在外层 IPv6 或不把 IPv4 总长作为约束的纯 UDP 语义中，UDP Length 字段上限为 **65535**。因此外层 IPv4 可承载的 L2TP payload 上限为 65507B（65515 − UDP 头 8B），不是 65527B。每个长度都必须先以无符号 32 位计算并校验，再写入线字段；超过所在承载层上限必须返回明确 validation/emit error，禁止转换为 `uint16` 后静默回绕或截断。边界契约为：内层 IPv4 Total Length 与内层 UDP Length 各自恰好 65535 可作为字段边界，但还必须满足其封装关系；外层 IPv4 UDP Length 恰好 65515 可作为有效边界，65516 即超出 IPv4 有效 UDP 上限；外层 IPv6/纯 UDP 的 65535 可作为字段边界，65536 必须拒绝。内层 payload 应按对应 L4 头部和外层 L2TP/UDP 封装反推最大值，并对每个相关字段的最大值与最大值+1分别登记测试。当前 `Validate` 未执行该检查，登记 G-L2TP-7；在该缺口关闭前，不得宣称已支持这些 uint16/承载上界。

## 3. 消息、事务与状态机

### 3.1 控制消息集合

支持的 `L2TPStep.Type` 与 Message Type AVP：`sccrq=1`、`sccrp=2`、`scccn=3`、`stopccn=4`、`hello=5`、`ocrq=6`、`ocrp=7`、`occn=8`、`icrq=9`、`icrp=10`、`iccn=11`、`cdn=12`、`wen=14`、`sli=15`、`zlb`（无 Message Type AVP）。`scenarios[]` 按数组顺序逐步各发一包；不自动补响应，响应必须显式列为下一步。

### 3.2 内置事务剧本

`scenario=tunnel_with_data` 在 `planner.go:633-641` 展开为：SCCRQ→SCCRP→SCCCN（RFC 2661 §4.1）→ICRQ→ICRP→ICCN（§4.3）→PPP 数据帧→StopCCN（§4.4）。当前唯一 JSON 用例正好是一帧数据，因此 8 包。单流协议，无控制流派生的独立子流；PPP 数据是控制隧道内的载荷，不是独立 flow。

角色默认 `lac`：LAC-originated 步骤方向 up，LNS-originated reply down；`lns` 时相反。Tunnel-level（SCCRQ/SCCRP/SCCCN/StopCCN/HELLO/ZLB）Session ID 强制 0；OCRP/ICRP 可用 peer session ID。up 使用 localNs，down 使用 peerNs，Nr 为对方当前计数器；初始 localNs=`InitialNs`、peerNs=0。每成功发包后对应方向 Ns 加一。

### 3.3 自动 AVP

SCCRQ/SCCRP：ProtocolVersion（缺省 0x0101）、FramingCaps、BearerCaps、HostName（缺省 trafficgen，含尾 NUL）、VendorName（缺省 trafficgen L2TP simulator，含尾 NUL）、AssignedTunnelID、ReceiveWindowSize（缺省 4）、TieBreaker（缺省 1）；可加 FirmwareRev。SCCCN：AssignedTunnelID。OCRQ/ICRQ：AssignedSessionID + CallSerialNumber=1。OCRP/ICRP、OCCN/ICCN：AssignedSessionID。StopCCN/CDN：Assigned ID + Result Code（缺省 ResultCode=1、ErrorMessage=user request）。HELLO/WEN/SLI 只带 Message Type（另加 custom AVP 时除外）。`custom_avps` 追加到每个消息，step AVPs 再追加于该步。

### 3.4 PPP 数据阶段

`InnerIP.DataFrames=0` 生成 1 帧；大于 0 生成 N 帧，每帧 IPID=i+1。`PPPFrames` 显式模式则逐项发出，方向缺省 up；LNS 角色会翻转方向。数据后若为内置剧本才发 StopCCN。

## 4. 校验、错误和确定性

`Validate` 先验证 outer IP 合法且同族、端口 0..65535、L2TPConfig 非空；版本仅 0/2/3，角色仅空/lac/lns；Scenario 仅 `tunnel_with_data`，且与 Scenarios/PPPFrames 互斥；HelloInterval≥0；v3 Cookie 仅 0/4/8/16；AVP 总长≤1023；step 类型必须已知；PPP Protocol 非 0；InnerIP 地址必须 IPv4、协议仅 1/6/17、DataFrames≥0。错误字面值由 `planner.go:156-334` 固定，任务层必须传播为失败而非成功零包。

Planner 是确定性的：同一配置、地址与序列产生同一包顺序和字节；时间戳为单次 Plan 的 `now`，IPID 从 1 开始。上下文取消停止发包。AVP 超限、unsupported version 等 emit 阶段错误不会向 channel 输出成功包。

## 4.1 规范要求→业务场景→代码现状→缺口矩阵

|规范要求|业务场景|代码现状|缺口/用例|
|---|---|---|---|
|RFC 2661 §4.1/§4.3 建隧道、建会话|`tunnel_with_data` 的 SCCRQ/SCCRP/SCCCN、ICRQ/ICRP/ICCN|`planner.go:633-641` 已生成|已由 `l2tp_smoke_01` 覆盖|
|RFC 2661 §4.4 拆隧道|StopCCN|`planner.go:647-650` 已生成|已由第 8 包覆盖|
|RFC 2661 §3.1 序号与 AVP|T 位、Version、Tunnel/Session、Ns/Nr、Message Type|`planner.go:555-601` 已生成|关键字段已覆盖，其余 AVP 缺口 G-L2TP-4|
|RFC 3931 v3|14B 控制头、32-bit Session、Cookie|`planner.go` 有 v3 分支|无 JSON 用例，G-L2TP-4|
|RFC 2661 §5.8 保活/异常|HELLO、ZLB、重试与超时|仅有 step/HelloInterval 表达力，无驱动重试器|G-L2TP-4/G-L2TP-6|
|层链唯一真相|`layers:[udp,l2tp]`，业务值在 `layers[].l2tp`|registry 已注册；`translateTerminalConfig` 无 l2tp case|G-L2TP-8（阻塞迁移）|

## 4.2 三来源与候选方案

|来源|结论|用途/当前状态|
|---|---|---|
|RFC 2661、RFC 3931、RFC 1661|L2TP 控制消息经 UDP 承载；v2 序号/AVP、v3 Cookie 与 PPP 语义按规范|规范底线，已实现部分见 §2–§3|
|商业软件行为|本轮没有可引用的产品版本、抓包或管理面证据|不得宣称现网覆盖；待确认，G-L2TP-4|
|可靠开源实现|本轮未锁定可复现版本/commit 的外部实现证据|只采用本仓库 Planner 作为实现依据，不冒充第三方验证|

|候选|优点|代价|裁定|
|---|---|---|---|
|A：层链翻译到 `spec.L2TP`，复用现有 Planner|单一线格式实现，改动小，兼容 pcap/NIC|当前 registry 没有 l2tp Fields，且需补终结层解码分支|选 A；G-L2TP-8 关闭前不迁移 case|
|B：层链生成器自行解析 raw map|绕开翻译缺口|重复解析/default/错误语义，易与 legacy 漂移|不选|

当前实现裁定：registry 仅登记 `udp` 依赖和 `udp.dst_port=1701`，没有 l2tp Fields；translate 也没有从终结层映射业务配置的分支。因此 `layers[].l2tp` 的 `scenario` 暂不能合法迁入 C，cases 保持现状并以 G-L2TP-8 登记。

## 4.3 依赖、错误、重试与超时

依赖顺序为 `udp → l2tp`；必须先完成层链补全、端口默认化和 `spec.L2TP` 翻译，再运行 `Planner.Validate`，最后由 l2tp 生成器向 UDP transport 发 MessageEvent。缺少配置、非法版本/IP/step/AVP/PPP 或长度越界必须同步返回错误并令任务失败；不得成功结束为 0 包。生成期 emit 错误或 context 取消中止当前计划并排空 channel（`layer_gen.go:71-74`）。

当前 Planner 没有重传器、重连器或可观测 ACK 超时状态机；HELLO 只由显式 step/`HelloInterval` 表达。因此重试、异常终止、长保活必须登记为未覆盖，不能把 `HelloInterval` 写成已支持的超时语义。后续验收至少区分控制消息重试、重连和会话中止三种结果，并记录 timeout 值及失败锚词。

## 4.4 性能设计与验收

生成路径逐包流式产出，不聚合整条流；每个事件暂存一份 payload，受上游有界队列、ring buffer 和输出路径限制。当前没有基准数字，吞吐、并发会话、最大内层报文、内存、队列、CPU 并行度均为待确认（G-L2TP-6）。验收必须分别运行 pcap 和真实 NIC，覆盖基线、目标规模、压力上限、长时、并发交错、背压/资源耗尽，并断言 packets/s、bits/s、延迟、内存、CPU、队列积压及丢包/失败，而非只断言任务未报错。

## 4.5 八要素实施条目

1. 文件：当前可核对 `internal/protocol/l2tp/{planner.go,layer_gen.go}`、`internal/core/layers/{registry.go,chain_planner_translate.go}`、`cases/l2tp.json`；迁移时再修改 cases 和补齐对应 translator/Fields（本轮禁止改代码）。
2. 接口：保持 `translateTerminalConfig(*core.FlowSpec)`、`LayerGenerator.Generate(ctx,*GenRequest) error`。
3. 数据结构：`layers[].l2tp` 解码为 `*L2TPConfig`，挂入 `FlowSpec.L2TP`。
4. 主流程：层链补全 → 翻译 → Validate → Planner Plan → UDP MessageEvent。
5. 错误分支：翻译/Validate/emit/context 任一失败，任务失败且无成功零包。
6. 性能边界：沿用有界队列与流式事件；具体阈值待 G-L2TP-6 基准确认。
7. 冲突点：当前旧顶层 `l2tp` 仍是唯一可执行配置，纯层链会因 G-L2TP-N 丢失业务配置。
8. 回滚：保留当前唯一 case 和 legacy translator，翻译分支验证失败时不改 cases，避免静默丢配置。

## 5. 五层覆盖

- **功能**：控制消息 15 类、ZLB、v2/v3 头、角色方向、Ns/Nr、AVP、PPP 数据和 StopCCN 均有实现；当前 JSON 只直接验证内置 v2 全链。未知 scenario、非法版本/角色/step、缺配置、AVP 超长、PPP Protocol=0 等负路径已由 validator 定义但未进入 cases。
- **性能**：控制 AVP 单项上限 1023B；数据帧数由 `DataFrames` 线性展开；单例 8 包；无 MSS 分段（UDP/L2TP 无 TCP MSS）。当前没有可宣称的吞吐/并发/长时指标：性能验收必须在后续补测中固定为（1）单流与多会话并发数及目标 packets/s、（2）单流最大内层报文、（3）内存与队列上限、（4）CPU 并行度、（5）pcap 与 NIC 两路丢包/背压结果，并覆盖基线、压力、长时、背压失败边界；上述测量方法和阈值尚未实现，登记 G-L2TP-6。大 AVP、最大数据帧、多帧用例待补。
- **数据**：默认和显式 tunnel/session ID、Ns/Nr、14 个消息类型、AVP M/H/vendor/type/value、PPP protocol、inner proto/ports/TTL/payload 均可配置；JSON 当前验证关键 Message Type、version、IDs、序号和 PPP 原始锚字节。v3 Cookie、边界 AVP、ICMP/TCP/UDP 变体待补。
- **地址与流**：outer IPv4/IPv6 同族校验由 Planner 支持；L2TP 的内层 `inner_ip` 只支持 IPv4（IPv6 inner 明确不适用）；单流基线已覆盖；控制流与数据流无独立关联，故流关联层不适用。L2TPv2 协议本身适用于一个 tunnel 承载多个独立 session；当前 planner 仅支持单组 session/PPPFrames，尚未实现多会话的独立状态隔离、建立/拆除生命周期、序列号和数据调度，登记 G-L2TP-6；因此“多会话”是当前实现未支持/未覆盖，不是协议不适用。
- **业务**：典型 LAC/LNS 建隧道、建立会话、承载 PPP IPv4、StopCCN 已由 `tunnel_with_data` 覆盖；HELLO 保活、OCR/OCN 呼叫、CDN、重试/重连、异常 RST/FIN 由现有 step/底座部分可表达但无 JSON 证据。现有协议为 UDP 无 FIN/RST。

## 6. 五件套与动态字段（§3 强制展开）

|项目|as-built 结论|
|---|---|
|会话表|单 tunnel/session：默认 local TunnelID=1，SessionID=0（tunnel-level），内置 ICRQ/ICRP/ICCN 使用会话；无 `sessions[]`。|
|事务序列|SCCRQ/SCCRP/SCCCN → ICRQ/ICRP/ICCN → PPP data → StopCCN；显式 `scenarios[]` 按数组顺序。|
|关联关系|Tunnel ID 贯穿控制/数据；Session ID 将 ICRQ/ICRP/ICCN 与数据关联；AVP Assigned IDs 由配置/默认生成。无父子数据流。|
|插入位置|Planner 在 UDP payload 内生成控制/数据；内置 PPP 数据插在会话建立与 StopCCN 之间；layer_gen 将每包交给 UDP transport。|
|时间线|单 Plan 的 `now` 作为 packet timestamps；HELLO 非首包且已有双方序号时等待 `HelloInterval`，默认 60s；其余无隐式延时。|

动态字段清单（当前策略转换没有协议字段的 fixed/inc/rand/list/pattern 生成器）：

|字段|四元组/业务|当前序号算法与证据|
|---|---|---|
|outer src_ip/dst_ip/src_port/dst_port|四元组|由层链/FlowSpec 取值；端口 0→1701，`strategy_convert.go:1197`、`chain_planner.go:1097`。|
|TunnelID|业务标识|0→local=1；每 Plan 固定，`planner.go:463-470`。|
|SessionID|业务标识|v2 16 位；v3 32 位为显式值，否则回退 16 位，`:471-482`。|
|Ns/Nr|业务序号|localNs=`InitialNs`、peerNs=0，按方向逐包递增，`:484-489,561-601`。|
|IPID|外层/内层序号|outer 每 emit 递增；inner 每数据帧 i+1，`:434-439,966-969`。|
|AVP/message fields|业务字段|由 config 固定/显式值生成；无策略级动态算法。|
|inner payload/ports/TTL|业务字段|`inner_ip` 逐 Plan 复制；DataFrames 仅按 i 生成 IPID。|

因此 `flows=N` 的协议关键字段动态策略、inc 回绕/rand 可复现/list 轮转/pattern 替换及静态重复告警**未实现/未覆盖**，登记 G-L2TP-2；不得把固定默认值声称为动态支持。

## 7. pcap/NIC 输出契约

pcap 与 NIC 使用同一 `cases/l2tp.json`、同一字段/frames/packet_count 断言；l2tp 只生成 UDP payload，NIC 捕获时外层链路地址可能变化，但协议 payload 断言不变。现有 tracked `trafficgen/docs/protocol-pcap-test/l2tp.md` 最后提交为 2026-08-27，早于 2026-09-13 判死提交 `0417be5`，且该车道未在本轮复跑，登记 G-L2TP-1；不以其“1 pass”作为当前证据。

## 8. 门1：§1–§14 对照表

|要求|本协议满足方式与证据|
|---|---|
|§1 顶层旧键|目标只有 `layers:[udp,l2tp]`；`l2tp` 配置住层内并由 `strategy_convert.go:1197` 解析；现有 case 已仅 `spec_json.l2tp` 旧形，登记 G-L2TP-3，迁移目标见 §1 JSON。|
|§2 规范依据|RFC 2661/3931、RFC 1661、791、768、793；线字段见 §2，代码 `planner.go:1109-1247`。|
|§3 五件套|会话/序列/关联/插入/时间线逐项见 §6；单 flow，无独立父子数据流。|
|§4 五层|功能、性能、数据、地址与流、业务逐层见 §5。|
|§5 术语|采用声明式剧本回放、事件/步骤、会话、事务、流关联；状态与驱动见 §3。|
|§6 代码可生成|字段偏移、端序、长度公式、默认值、自动 AVP、状态和错误见 §2–§4。|
|§7 原子用例|当前机器契约仅 1 条集成冒烟；原子缺口逐条登记 G-L2TP-4。|
|§8 审查|本轮自审；独立代码/覆盖对抗审查待主线程安排，不能宣称 clean。|
|§9 输出|pcap/NIC 共用契约见 §7。|
|§10 动态字段|四元组和业务字段清单见 §6；动态策略缺口 G-L2TP-2。|
|§11 层接线|registry `registry.go:506`，layer_gen `layer_gen.go:36-105`，UDP 依赖与端口链路见 §0。|
|§12 关键字段|Tunnel/Session/Ns/Nr、AVP、PPP、inner IPv4 逐项见 §2、§3、§6。|
|§13 错误处理|Validate 规则和字面锚词见 §4；现有 cases 无负例，见 G-L2TP-4。|
|§14 产物与边界|过期结果登记 G-L2TP-1；未覆盖 v3/动态/负例明确排除，见 G-L2TP-2…4。|

## 9. 缺口登记

|ID|现象|证据|归属阶段|
|---|---|---|---|
|G-L2TP-1|tracked l2tp 结果文档过期，未证明本轮复跑|`trafficgen/docs/protocol-pcap-test/l2tp.md` commit 2026-08-27 < `0417be5`|P4 复跑|
|G-L2TP-2|策略级动态字段与 N 流确定性展开未落地|`strategy_convert.go:1197` 仅静态 parse；`L2TPConfig` 无 strategy 字段|P4 接线|
|G-L2TP-3|现有 JSON 顶层为旧 `l2tp` 子映射，非目标纯层链|`cases/l2tp.json:6-10`；目标形 §1|P4 迁移|
|G-L2TP-4|仅 1 条正例，缺 v3、ZLB、各控制步、边界/错误/IPv6 与内层协议变体|`cases/l2tp.json` 唯一 ID|P3/P4 覆盖|
|G-L2TP-5|Planner 发包内部错误只停止 channel，未形成显式错误返回|`planner.go:573-576`|P4 错误传播|
|G-L2TP-6|多会话状态/生命周期/调度未实现；吞吐、并发、资源、长时、背压等性能阈值和测量未落地|planner 仅单组 `LocalSessionID/PeerSessionID`/`PPPFrames`；现有 case 仅 8 包，无资源或吞吐断言|P3/P4 实现与验收|
|G-L2TP-7|内层 IPv4 Total Length、内层 UDP Length 与外层承载 UDP Length 尚未由 Validate 分层计算并拒绝 65536|本节长度契约；当前 `Validate` 未执行长度上界检查|P4 边界校验与负例|
|G-L2TP-8|`layers[].l2tp` 尚未翻译为 `spec.L2TP`，且 registry 没有 l2tp Fields；纯层链配置会丢失 scenario|`registry.go:507-510` 仅有 UDP 依赖/端口 FieldContract；`chain_planner_translate.go:756-` 无 `term.Name == "l2tp"` 分支|P4 层接线后迁移|

## 10. 修订记录与自审

- 2026-10-01：复核 registry、strategy_convert、translateTerminalConfig 与 chain planner；确认 l2tp 层内翻译缺少 `case "l2tp"`，将迁移阻塞和当前 C 形状写实化。
- 自审 2 轮，末轮干净：第 1 轮核对目标/存量形状、默认端口和代码引用；第 2 轮核对字段/长度/状态机与 G-L2TP-3、G-L2TP-7 口径。

## 11. D1–D8 静态设计闭环

| ID | 必核对项 | 结论与证据 |
|---|---|---|
| D1 | 范围、profile、实现边界 | UDP 承载 L2TPv2/v3；当前可执行 profile 仅 v2 `tunnel_with_data`，v3/扩展面列为 G-L2TP-4。|
| D2 | 层链、承载和默认端口 | 目标链为 `[udp,l2tp]`，业务值住 `layers[].l2tp`，目的端口缺省 1701；`translateTerminalConfig` 缺少 `case "l2tp"`，登记 G-L2TP-8，不把目标形写成已执行。|
| D3 | 线格式、偏移、端序和长度 | v2 控制头 12B、数据头 4B、AVP 6B、网络字节序；长度公式和 PPP offset 见 §2，内外层长度上限分层，G-L2TP-7 未实现。|
| D4 | 状态机、事务和自动派生 | `tunnel_with_data` 固定 8 包序列；显式 steps 不自动补响应；Ns/Nr、AVP、PPP 插入和 StopCCN 见 §3。|
| D5 | 校验与错误传播 | `Planner.Validate` 的真实锚词为 `L2TP config is required`、`Scenario ... unknown`、`cannot both be set`、`exceeds max 1023`、`Cookie length ... invalid` 等；任务层错误终态传播仍是 G-L2TP-5。|
| D6 | 性能、容量和双输出 | 逐包流式生成；AVP ≤1023B，数据帧按 `DataFrames` 展开；吞吐/并发/背压尚无基准。pcap/NIC 共用同一断言，未运行不宣称通过。|
| D7 | 动态字段与数量边界 | 外层四元组由承载层提供；L2TP 业务字段无 fixed/inc/rand/list/pattern 序列生成，`flows=N` 动态整格登记 G-L2TP-2。|
| D8 | 门1三行与回滚边界 | §1 旧键去向、§6 五件套/动态清单、§9 对照表均已列出；代码接线前保留当前 legacy case，不迁移 JSON，失败时回滚不丢唯一可执行输入。|

## 12. C1–C6 三件套静态核对

| ID | 核对项 | 结论 |
|---|---|---|
| C1 | JSON 可解析、唯一 ID、D/T/C 对账 | 当前仅 `l2tp_smoke_01`，1 正例、0 负例、8 包；ID、字段和帧锚点与 testcase §2 一致。|
| C2 | 顶层白名单与旧键残留 | 当前 `spec_json` 只有顶层 `l2tp`，没有 `layers`，不是严格层链；残留为 G-L2TP-3，禁止申报旧键清零。|
| C3 | 地址/端口/业务归属 | 目标业务应在 `layers[].l2tp`、端口在 `layers[].udp`；当前 `scenario` 仍在顶层且无 `layers`，层内翻译阻塞 G-L2TP-8。|
| C4 | 正负 expect 纯净性与真实锚词 | 正例保留 `packet_count`、fields、frames；负例集合为空。未来负例必须严格只有 `expect_error` 与 `error_contains`，锚词逐字取 `planner.go:156-334`，不得写双键以外字段。|
| C5 | 行为面与缺口 | 已对账 v2 建隧道/会话/PPP/StopCCN；HELLO、ZLB、v3、边界、IPv6、内层变体、动态和异常分支均保持 G-L2TP-2/4/6/7，未伪造 ID。|
| C6 | registry/翻译与双路径边界 | registry/layer generator 已有 l2tp 注册和 UDP 依赖，但层内终结翻译缺口 G-L2TP-8；本轮未运行 suite、MCP、NIC、Go 或服务器。|

上述 D1–D8/C1–C6 是静态文档闭环，不等价于层链迁移、真实 PCAP/NIC 运行或错误终态验收。
