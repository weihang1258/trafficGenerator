# IKE-NAT-T（IKEv2 NAT Traversal）设计契约

> 版本：v1.0.0（as-built）；日期：2026-09-29；协议名：`ike_nat_t`；权威用例：`trafficgen/test/protocol_pcap/cases/ike_nat_t.json`。
> 本文只描述当前实现与唯一现存 case，不把未覆盖的 NAT-T 扩展写成已验收能力。

## 1. 范围、配置真相与旧键审计

IKE-NAT-T 是 UDP 终结层的 IKEv2 NAT 穿越变体：可在端口 500/4500 间浮动，在 4500 的 IKE 消息前加入 4-byte Non-ESP Marker；实现还包含 NAT-D、UDP-ESP、keepalive、重传和 Child SA 分支。入口为 `trafficgen/internal/protocol/ike_nat_t/{planner.go,layer_gen.go}`，配置类型为 `IKENATTConfig`（`internal/core/types.go:4526-4566`）。

**存量形状机读基线**：`cases/ike_nat_t.json` 唯一例 `spec_json` 顶层键 = `{count,dst_port,ike_nat_t}`，无 `layers`，属扁平残留（G-NATT-3），不能把目标层链形当成现状。

旧/扁平键逐键去向：

| 旧键 | 存量出现 | 去向 |
|---|---:|---|
| `count` | 1/1 | 公共任务计数；目标形由 `flow_control` 承载 |
| `dst_port` | 1/1 | 公共 UDP transport；目标形迁 `layers[0].udp.dst_port` |
| `ike_nat_t` | 1/1 | `spec.IKENATT`；目标形迁 `layers[1].ike_nat_t` |
| `src_ip`/`dst_ip`/`src_port` | 0 | 公共地址/端口缺省，不在此 case 显式声明 |

目标形状（**迁移目标，非存量事实**）：

```json
{"layers":[{"udp":{"dst_port":500}},{"ike_nat_t":{"dialog":[{"direction":"up","exchange_type":34}]}}],"flow_control":{"flows":1}}
```

Registry 将其注册为 UDP terminal、依赖 udp、默认目的端口 4500（`internal/core/layers/registry.go:536-543`）。

## 2. 协议栈、端口与偏移

线序 Ethernet → IP → UDP → [Non-ESP Marker] → IKE header。IKE header 固定 28B，v2 version=0x20；SA_INIT=34。端口 500 的 IKE message 不加 marker；端口 4500 的 IKE message 加 `00 00 00 00`，ESP-in-UDP 与 keepalive 为独立 payload 形状。唯一 case 显式 dst=500，故 packet 1 UDP payload 从 offset 42 起直接为 IKE header，marker 不适用。

## 3. 线格式、五件套与动态字段

IKE header 为 `SPIi(8)|SPIr(8)|NextPayload(1)|Version(1)|ExchangeType(1)|Flags(1)|MessageID(4)|Length(4)`；通用 payload header 为 4B。NAT-D 使用 Notify payload type=41，通知类型 16388/16389，SHA-1 数据长度 20B（RFC 7296 §2.23）；Non-ESP Marker 按 RFC 3948 为 4 个零字节。

动态字段清单（四元组 + 业务字段逐个）：① `InitiatorSPI/ResponderSPI`，`generateSPI`/dialog 学习逻辑（`planner.go:217-233`、`828-856`）；② `src_ip,dst_ip,src_port,dst_port`，由公共 FlowSpec 进入 `computeNATDHash`（`planner.go:688-735,839-856`）；③ NAT-D source/destination hash，SHA-1 20B；④ message direction/exchange/message_id/payloads，按 `IKENATTMessage`（types.go:4589-4621）和 `runPlan` 序列化；⑤ marker/UDP port，`runPlan` 的 NAT detected + PortFloat 分支；⑥ ESP SPI/seq/IV/ICV，`emitESPSubFlows`（`planner.go:451-543`）；⑦ keepalive byte 0xFF/count/interval，`emitKeepaliveSubFlows`（`planner.go:545-652`）；⑧ retransmit timeout/max/backoff，`applyDefaults`（`planner.go:654-686`）。

五件套：会话表=一条 IKE SA；事务序列=case 的一条 SA_INIT header-only message；关联关系=SPIi/SPIr + MessageID；插入位置=UDP payload（4500 时 marker 在 IKE 前）；时间线=dialog 顺序。单消息 case 豁免完整 SA 状态机、响应配对和 NAT-D payload，因为 JSON 明确只构造 header-only SA_INIT。

## 4. 五层覆盖

- 功能层：header-only SA_INIT initiator，exchange=34，空 payload；marker 分支存在但本 case 端口 500 不触发。
- 性能层：planner channel 逐消息产出；UDP 无握手；重传/keepalive 是可选独立子流，本 case 不启用。
- 数据层：28B header、SPI、version、exchange、flags、length=28；frames 钉定 offset 58（Ethernet/IP/UDP 后 16B? JSON frame bytes 为 probe 的 IKE header稳定片段）。
- 地址与流层：UDP dst=500；src/dst IP 由公共层默认；单 datagram；无 NAT port float。
- 业务层：IKEv2 SA_INIT header 语义；不宣称 NAT 已检测，因为 case 未设置 NATDetection。

## 5. 状态机与边界

正常实现可由 dialog 生成 SA_INIT→AUTH→Child SA；NAT 检测后可 500→4500 浮动，marker/ESP/keepalive 分别插入。当前 case 时间线只有一条 up 方向 SA_INIT header，`rspi=0` 且 MessageID=0。TCP、真实加密、服务端 NAT 观测、双向协商均不在该 case。

## 6. 性能与错误处理

`Plan` 校验后创建 buffered channel（`planner.go:217-231`），`runPlan` 逐项写入并关闭；generator 复用 planner、逐事件发送且设置 `L4PortOverride=true`（`layer_gen.go:31-82`）。Validate 拒绝非法 IP、缺 config、坏 direction/exchange、坏 nonce、NAT-D 非 20B、负 max retransmit、backoff<1；Generate 拒绝 nil EmitMsg/config。错误必须返回，不得 0 包假绿。

## 7. 原子 ID 与完成定义

唯一 ID 是 `ike_nat_t_sa_init_header_only`（1 正、0 负）。完成定义：至少 1 包；UDP dst 500；SPIi 非零、SPIr 全零；version=0x20、exchange=34、flags=0x08、length=28；frame offset 58 的稳定 12B 为 `00 20 22 08 00 00 00 00 00 00 00 1c`。随机 SPI 不固定。

## 8. 规范矩阵

|规范|场景|代码证据|缺口|
|---|---|---|---|
|RFC 7296 §3.1|header-only SA_INIT|`buildIKENATTMessage:858-910`|无|
|RFC 7296 §2.23|NAT-D Notify|`computeNATDHash:839-856`|本 case 未覆盖|
|RFC 3948|marker/UDP-ESP|`runPlan`, `emitESPSubFlows`|G-NATT-1|
|RFC 3947/7296|端口浮动|`runPlan` NAT detected 分支|G-NATT-1|
|RFC 7296 §2.2|重传|`handleRetransmits:410-449`|本 case 未覆盖|
|RFC 3948|keepalive|`emitKeepaliveSubFlows:545-652`|本 case 未覆盖|
|IKEv2 payload format|SA/KE/Nonce|`encodeNATTPayloads:911-1042`|本 case 空 payload|
|ESP|Child SA data plane|`emitESPSubFlows`|本 case 未覆盖|

## 9. 门1 §1–§14 对照表

| § | 本协议满足方式 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 存量唯一例顶层 `{count,dst_port,ike_nat_t}`，无 `layers`，G-NATT-3；旧键逐键去向与完整目标形见 §1 | §1；`cases/ike_nat_t.json` |
| §2 策略/任务 | 策略 = 单 header/dialog 模板；任务 = flow count 扩展与总量封顶；存量 `count` 为旧形公共任务键 | §1/§3 |
| §3 五件套 | 会话表 = 单 IKE SA；事务 = header-only SA_INIT；关联 = SPIi/SPIr + MessageID；插入 = UDP payload（4500 marker 在 IKE 前）；时间线 = `dialog` 顺序；单消息例不虚报完整状态机 | §3/§5 |
| §4 查规范 | RFC 7296 §3.1/§2.23 + RFC 3948/3947 + RFC 4303 + RFC 7296 §2.2 | §8 |
| §5 依赖与错误 | `DependsOn ["udp"]`（registry:540）；非法 IP/缺 config/坏 dialog、NAT-D 长度、重传参数均 validator 拒绝并传 task error | §6/§10 |
| §6 性能 | Plan buffered channel 逐消息，marker/ESP/keepalive/重传边界写明；pcap/NIC 共用 cases 断言 | §6/testcase §1 |
| §7 三份文档 | `142-ike_nat_t-{design,testcase}.md` + `cases/ike_nat_t.json`；现有 1 ID/包下限/字段/frame 一致 | testcase §2/§5 |
| §8 设计先行 | 本文 as-built 逆向定稿，未覆盖分支明确列缺口 | 修订记录 |
| §9 测试三源 | RFC + 本设计 + tshark `isakmp.*`/frame hex；唯一 ID 逐项回指 testcase §2/§3 | testcase §5 |
| §10 评审闭环 | 自审与机读形状核对；独立对抗复审由主线程另行派发 | 修订记录 |
| §11 白话 | 首节白话（协议作用）与测试白话（testcase 首节） | 全文 |
| §12 动态字段 | 四元组 + SPI/NAT-D hash/marker/port/ESP/keepalive/retransmit 逐个列算法位置 | §3 |
| §13 schema 派生 | `ike_nat_t` 已注册 registry:540（不新增层），layer_gen:107；Fields 空，配置经 spec.IKENATT 携带 | §10 |
| §14 真实流程 | MCP → task → UDP → generator legacy Plan → tshark/frame 双路断言；结果产物过期登记 G-NATT-2 | §10/testcase §8 |

## 10. 接线与验证

`IKENATTGenerator.Generate` 构造 FlowSpec 并复用 Planner；registry/layer init 分别位于 `registry.go:540`、`layer_gen.go:107-114`；strategy conversion 位于 `internal/core/strategy_convert.go:1185-1188`。主线程应运行 JSON parser、ID/expect/frame 静态检查和 tshark `isakmp` 字段核验。

## 11. 缺口登记（三要素）

|ID|现象|证据|归属阶段|
|---|---|---|---|
|G-NATT-1|NAT-D、4500 marker、ESP、keepalive、重传和负例均无现存 JSON 用例|JSON 只有 header-only dst 500；实现分支见 §8|P3/P4 用例扩展|
|G-NATT-2|tracked 结果产物过期且无 pcap 留档，历史 pass 数未经今日复跑证实|`git log`：`e7e7d1c` 2026-08-27 < `0417be5` 2026-09-13；`protocol-pcap-test/ike_nat_t/` 不存在|P5 重跑并重生成产物|
|G-NATT-3|存量唯一 case 顶层键 `{count,dst_port,ike_nat_t}`，无 `layers`，层链门不通过|机读 `cases/ike_nat_t.json`|P4 cases 迁移|
|G-NATT-4|`CheckProtoFlat` 未登记 ike_nat_t presence，presence 负例会假绿|`strategy_convert.go` 对 `protocol == "ike_nat_t"` 无分支|P6 框架面|
|G-NATT-5|dynamic allowlist 无 ike_nat_t 业务字段，动态字段对象不可用|`layer_dyn.go` 头部无 ike_nat_t 行|P6 框架面|

## 12. 覆盖反查门建议断言

|#|可静态机读断言|状态|
|---:|---|---|
|1|ID 恰为 `ike_nat_t_sa_init_header_only`，顺序 1|绿|
|2|正=1、负=0、`min_packets=1`|绿|
|3|dstport=500，SPIi nonzero，SPIr exact zero|绿|
|4|version=0x20、exchange=34、flags=0x08、length=28|绿|
|5|frame offset=58，hex 精确为 `00 20 22 08 00 00 00 00 00 00 00 1c`|绿|
|6|层链迁移后顶层键 ⊆ `{layers}`|**红：今日为 `{count,dst_port,ike_nat_t}`，G-NATT-3**|
|7|负例锚词集合非空且 validator 每类错误至少一例|**红：0 负例，G-NATT-1**|

pcap/NIC 两路必须复用同一断言集，不能用过期结果产物代替复跑。

## 13. 修订记录

- v1.0.1（2026-09-29）：批次二门1补齐 §1 逐键去向/目标形状、§1–§14 十四行表、五层与五件套、存量扁平 G-NATT-3、产物过期 G-NATT-2、框架缺口 G-NATT-4/5、反查红项；**自审 2 轮，末轮干净**。
- v1.0.0（2026-09-29）：按现有实现与 `ike_nat_t.json` 建立 as-built 文档。
