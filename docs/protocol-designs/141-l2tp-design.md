# #141 L2TP 设计契约

> 版本：v1.0.0（as-built，文档轨批次二）
> 日期：2026-09-29
> 依据：RFC 2661（L2TPv2）§3–§5、§7，RFC 1661 §6，RFC 791 §3.1，RFC 768，RFC 793，RFC 3931 §3、§5；现有 planner/layer_gen/types/registry 与 `cases/l2tp.json`。
> 范围：UDP 承载的 L2TPv2/v3 控制消息和 PPP 数据消息；当前机器契约仅落地 L2TPv2 `tunnel_with_data`。

## 0. As-built 边界

`internal/protocol/l2tp/planner.go` 的 `Planner.Validate` 与 `Plan` 是线格式和默认值权威；`layer_gen.go:36-77` 复放 Planner 的 `PacketConfig` 为 `MessageEvent`，并固定 `L4PortOverride=true`，避免 UDP 层再次交换方向端口。registry `registry.go:506` 将 l2tp 注册为 `CategoryTerminal`、依赖 `udp`；`strategy_convert.go:1197-1200` 解析层内 `l2tp`，chain planner 在 `:1097-1101` 缺省目的端口 1701。当前 cases 只有 `l2tp_smoke_01`（8 包），文档不把未落入 JSON 的能力冒充已覆盖。

## 1. 配置形状、输入与输出

纯层链形（顶层无游离 l2tp 键）：

```json
{
  "layers": [
    {"udp": {"dst_port": 1701}},
    {"l2tp": {"scenario": "tunnel_with_data"}}
  ]
}
```

层链进入 `FlowSpec` 后由 `parseL2TPConfig` 形成 `spec.L2TP`。外层四元组来自 IP/UDP 层；缺省目的端口为 1701，Planner 自身对源/目的端口均为 0 时也用 1701（legacy flow 默认源端口 12345 在完整链路中保留）。缺省 outer IP/MAC 由框架/Planner 兜底，outer protocol 固定 UDP，TTL 缺省 64。

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

`inner_ip` 仅允许 IPv4。IPv4 头固定 20B、IHL=5、DF、TTL 默认 64、IPID 从 1 按数据帧递增，协议支持 ICMP(1)、TCP(6)、UDP(17)，默认 UDP。UDP 头 8B、checksum=0；TCP 头 20B、窗口 65535、计算伪首部 checksum；ICMP echo request 8B、计算 checksum。内层总长为 `20 + L4Header + len(Payload)`；IPv4 checksum 按 RFC 791。

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

## 5. 五层覆盖

- **功能**：控制消息 15 类、ZLB、v2/v3 头、角色方向、Ns/Nr、AVP、PPP 数据和 StopCCN 均有实现；当前 JSON 只直接验证内置 v2 全链。未知 scenario、非法版本/角色/step、缺配置、AVP 超长、PPP Protocol=0 等负路径已由 validator 定义但未进入 cases。
- **性能**：控制 AVP 单项上限 1023B；数据帧数由 `DataFrames` 线性展开；单例 8 包；无 MSS 分段（UDP/L2TP 无 TCP MSS），内层 payload 受 IPv4 total length uint16 实现上限约束。大 AVP、最大数据帧、多帧用例待补。
- **数据**：默认和显式 tunnel/session ID、Ns/Nr、14 个消息类型、AVP M/H/vendor/type/value、PPP protocol、inner proto/ports/TTL/payload 均可配置；JSON 当前验证关键 Message Type、version、IDs、序号和 PPP 原始锚字节。v3 Cookie、边界 AVP、ICMP/TCP/UDP 变体待补。
- **地址与流**：outer IPv4/IPv6 同族校验由 Planner 支持；L2TP 的内层 `inner_ip` 只支持 IPv4（IPv6 inner 明确不适用）；单流基线已覆盖；控制流与数据流无独立关联，故流关联层不适用。多流/多会话不适用：当前剧本为一个 tunnel/session，需多 flow 策略由框架展开，协议 planner 不交错。
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

## 10. 修订记录与自审

- 2026-09-29：初稿，按实现/cases 反推；登记 G-L2TP-1…5。
- 自审 2 轮，末轮干净：第 1 轮核对配置字段、控制/数据偏移、v2/v3 长度、8 包序列；第 2 轮脚本核对 case ID/包数/断言与本文引用，确认未改代码/cases。独立对抗审查仍待安排。
