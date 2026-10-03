# IKE-NAT-T（IKEv2 NAT Traversal）设计契约

> 版本：v1.1.0（层链迁移版）；日期：2026-09-30；协议名：`ike_nat_t`；权威用例：`trafficgen/test/protocol_pcap/cases/ike_nat_t.json`。
> 本文只描述当前实现与唯一现存 case，不把未覆盖的 NAT-T 扩展写成已验收能力。

## 1. 范围、配置真相与旧键审计

IKE-NAT-T 是 UDP 终结层的 IKEv2 NAT 穿越变体：可在端口 500/4500 间浮动，在 4500 的 IKE 消息前加入 4-byte Non-ESP Marker；实现还包含 NAT-D、UDP-ESP、keepalive、重传和 Child SA 分支。入口为 `trafficgen/internal/protocol/ike_nat_t/{planner.go,layer_gen.go}`，配置类型为 `IKENATTConfig`（`internal/core/types.go:4526-4566`）。

**形状基线**：JSON 唯一例 `spec_json` 顶层仅 `{layers}`，链 `[ip,udp,ike_nat_t]`；地址住 `ip`、端口住 `udp`、业务住终结层，无游离键，无协议子映射混入。

旧/扁平键逐键去向：

| 旧键 | 存量出现 | 去向 |
|---|---:|---|
| `count` | 0 | 本例为单流；数量由 `flow_control` 承载，未写 `count` |
| `dst_port` | 0 | `layers[].udp.dst_port` |
| `ike_nat_t` 顶层子映射 | 0 | `layers[].ike_nat_t` |
| `src_ip`/`dst_ip`/`src_port` | 0 | 本例不显式声明；地址与端口按层链规则承载 |

严格层链形状（权威正例）：

```json
{"layers":[{"ip":{"src":"10.0.0.1","dst":"20.0.0.1"}},{"udp":{"dst_port":500}},{"ike_nat_t":{"dialog":[{"direction":"up","exchange_type":34}]}}]}
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
- 数据层：28B header、SPI、version、exchange、flags、length=28；IKE header 起点 offset 42（Ethernet 14B + IPv4 20B + UDP 8B），前置 SPIi 8B 与 SPIr 8B 后在 offset 58 钉定 `next_payload|version|exchange|flags|msgid|length` 稳定片段。
- 地址与流层：UDP dst=500；src/dst IP 由公共层默认；单 datagram；无 NAT port float。
- 业务层：IKEv2 SA_INIT header 语义；不宣称 NAT 已检测，因为 case 未设置 NATDetection。

## 5. 状态机与边界

正常实现可由 dialog 生成 SA_INIT→AUTH→Child SA；NAT 检测后可 500→4500 浮动，marker/ESP/keepalive 分别插入。当前 case 时间线只有一条 up 方向 SA_INIT header，`rspi=0` 且 MessageID=0。TCP、真实加密、服务端 NAT 观测、双向协商均不在该 case。

## 6. 性能与错误处理

`Plan` 校验后创建 buffered channel（`planner.go:217-231`），`runPlan` 逐项写入并关闭；generator 复用 planner、逐事件发送且设置 `L4PortOverride=true`（`layer_gen.go:31-82`）。Validate 拒绝非法 IP、缺 config、坏 direction/exchange、坏 nonce、NAT-D 非 20B、负 max retransmit、backoff<1；Generate 拒绝 nil EmitMsg/config。错误必须返回，不得 0 包假绿。性能目标与双路验收法见 §14.4（基准待 G-NATT-6）。

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
| §1 层链唯一真相 | 唯一例顶层仅 `{layers}`，链 `[ip,udp,ike_nat_t]`；旧键逐键去向与完整形见 §1 | §1；`cases/ike_nat_t.json` |
| §2 策略/任务 | 策略 = 单 header/dialog 模板；数量由 `flow_control` 承载（本例单流不写） | §1/§3 |
| §3 五件套 | 会话表 = 单 IKE SA；事务 = header-only SA_INIT；关联 = SPIi/SPIr + MessageID；插入 = UDP payload（4500 marker 在 IKE 前）；时间线 = `dialog` 顺序；单消息例不虚报完整状态机 | §3/§5 |
| §4 查规范 | RFC 7296 §3.1/§2.23 + RFC 3948/3947 + RFC 4303 + RFC 7296 §2.2 | §8/§14.1 |
| §5 依赖与错误 | `DependsOn ["udp"]`（registry:540）；非法 IP/缺 config/坏 dialog、NAT-D 长度、重传参数均 validator 拒绝并传 task error | §6/§14.3 |
| §6 性能 | Plan channel 逐消息；目标基准待 G-NATT-6；pcap/NIC 双路验收 | §14.4 |
| §7 三份文档 | 本设计、testcase、`cases/ike_nat_t.json`；1 ID/包下限/字段/frame 一致 | testcase §2/§5 |
| §8 设计先行 | 层链迁移与 D1–D8 补充已定稿，未覆盖分支登记 G-NATT-1 | §14/修订记录 |
| §9 测试三源 | RFC + 本设计 + tshark `isakmp.*`/frame hex；唯一 ID 逐项回指 testcase §2/§3 | testcase §5 |
| §10 评审闭环 | 自审 2 轮，末轮干净；独立对抗复审由主线程另行派发 | 修订记录 |
| §11 白话 | 首节说明协议作用与当前边界 | 全文 |
| §12 动态字段 | 四元组 + SPI/NAT-D hash/marker/port/ESP/keepalive/retransmit 逐个列算法位置 | §14.6 |
| §13 schema 派生 | `ike_nat_t` 已注册 registry:540（不新增层），layer_gen:107；业务配置在终结层 | §10 |
| §14 真实流程 | MCP → task → UDP → generator → tshark/frame 双路断言；复跑产物待 G-NATT-2 | §10/testcase §8 |

## 10. 接线与验证

`IKENATTGenerator.Generate` 构造 FlowSpec 并复用 Planner；registry/layer init 分别位于 `registry.go:540`、`layer_gen.go:107-114`；strategy conversion 位于 `internal/core/strategy_convert.go:1185-1188`。主线程应运行 JSON parser、ID/expect/frame 静态检查和 tshark `isakmp` 字段核验。

## 11. 缺口登记（三要素）

|ID|现象|证据|归属阶段|
|---|---|---|---|
|G-NATT-1|NAT-D、4500 marker、ESP、keepalive、重传和负例均无现存 JSON 用例；P3/P4 按 §14.1 表扩展，商业行为确认方式为现网网关抓包|JSON 只有 header-only dst 500；实现分支见 §8|P3/P4 用例扩展|
|G-NATT-2|结果产物过期且无 pcap 留档，历史 pass 数未经今日复跑证实|`git log`：`e7e7d1c` 2026-08-27 < `0417be5` 2026-09-13；`protocol-pcap-test/ike_nat_t/` 不存在|P5 重跑并重生成产物|
|G-NATT-4|`CheckProtoFlat` 未登记 ike_nat_t presence，presence 负例会假绿|`strategy_convert.go` 对 `protocol == "ike_nat_t"` 无分支|P6 框架面|
|G-NATT-5|dynamic allowlist 无 ike_nat_t 业务字段，动态字段对象不可用|`layer_dyn.go` 头部无 ike_nat_t 行|P6 框架面|
|G-NATT-6|吞吐、并发流数、最大报文、缓冲上限、CPU 并行度和双路验收基准缺失；不作承诺|本设计此前无 §6 数据，以待确认登记|P5 性能取证|

## 12. 覆盖反查门建议断言

|#|可静态机读断言|状态|
|---:|---|---|
|1|ID 恰为 `ike_nat_t_sa_init_header_only`，顺序 1|绿|
|2|正=1、负=0、`min_packets=1`|绿|
|3|dstport=500，SPIi nonzero，SPIr exact zero|绿|
|4|version=0x20、exchange=34、flags=0x08、length=28|绿|
|5|frame offset=58，hex 精确为 `00 20 22 08 00 00 00 00 00 00 00 1c`|绿|
|6|顶层键 = `{layers}`；链 `[ip,udp,ike_nat_t]`；无游离键、无顶层业务子映射|绿|
|7|负例锚词集合非空且 validator 每类错误至少一例|**红：0 负例，G-NATT-1**|

pcap/NIC 两路必须复用同一断言集，不能用过期结果产物代替复跑。

## 14. D1–D8 补充契约

### 14.1 D1 规范要求→场景→代码→缺口矩阵

|规范要求|业务场景|代码现状|缺口/用例|
|---|---|---|---|
|连接模型（RFC 7296 §3.1）|UDP 上 IKEv2 SA_INIT|`planner.go:858-910` 逐消息编码|已覆 `ike_nat_t_sa_init_header_only`|
|请求/响应与 payload（RFC 7296 §2.2/§3.1）|SA_INIT→AUTH→Child SA|`runPlan` 按 dialog 序列发送|AUTH/Child SA 未入例，G-NATT-1|
|状态机（RFC 7296 §2.1）|建 SA、业务、释放|`runPlan` 支持 dialog 顺序|完整状态迁移未入例，G-NATT-1|
|字段（RFC 7296 §3.1）|SPI、版本、交换类型、标志、长度|`buildIKENATTMessage:858-910`|header-only 已覆；payload 字段待扩展|
|错误（RFC 7296 §2.2）|非法 dialog/IP/nonce|validator 在 `planner.go:217-231`|负例未入 cases，G-NATT-1|
|活性/重传（RFC 7296 §2.2）|重传、keepalive|`handleRetransmits:410-449`、`emitKeepaliveSubFlows:545-652`|未入例，G-NATT-1|
|NAT/代理（RFC 3948/3947）|NAT-D 后浮动到 UDP 4500|`runPlan` NAT detected 分支|未入例，G-NATT-1|
|版本/方言（RFC 7296/3948）|IKEv2、Non-ESP marker、UDP-ESP|`runPlan` marker/ESP 分支|4500、ESP 未入例，G-NATT-1|

**命令×响应码矩阵（IKEv2 exchange/message）**：SA_INIT request = 已覆（header-only）；SA_INIT response = 缺口 G-NATT-1；AUTH request/response = 缺口 G-NATT-1；CREATE_CHILD_SA request/response = 缺口 G-NATT-1；INFORMATIONAL request/response = 缺口 G-NATT-1；Notify/NAT-D payload = 缺口 G-NATT-1。IKEv2 不使用 HTTP 式响应码，响应由 exchange、direction、payload 状态表达。

**数据形态变体表**：UDP 500 无 marker（已覆）；UDP 4500 + 4-byte Non-ESP marker（G-NATT-1）；NAT-D SHA-1 20B Notify（G-NATT-1）；ESP-in-UDP（G-NATT-1）；keepalive `0xff`（G-NATT-1）；重传序列（G-NATT-1）；空 payload header（已覆）。

**商业行为→用例映射表**：主流 IKEv2 设备的 500 SA_INIT → `ike_nat_t_sa_init_header_only`；NAT 后切 4500 → G-NATT-1（确认方式：对接一台现网 VPN 网关并抓取 SA_INIT/NAT-D）；4500 keepalive → G-NATT-1（同抓包确认）；ESP-in-UDP → G-NATT-1（同抓包确认）。

### 14.2 D2 三路对照与方案选择

|来源|结论|
|---|---|
|RFC 7296 §3.1、§2.23；RFC 3948 §2|IKE header 固定字段，NAT-D 为 Notify，4500 的 IKE 前有 Non-ESP marker|
|商业 VPN 网关行为（待实网抓包）|NAT 检测后通常切换 UDP 4500，并以 marker 区分 IKE 与 ESP；待 G-NATT-1 实证|
|strongSwan 6.x `charon` IKEv2 实现思路|把 IKE 控制消息与 ESP/keepalive 分成不同事件，按协商状态选择承载|

|候选走法|优点|代价|选择|
|---|---|---|---|
|A：每个 dialog 事件直接编码完整 IKE/marker|复用现有 planner，流式、改动小|完整协商状态需由配置表达|当前采用|
|B：引入独立 SA 状态机并自动协商|更接近真实端点|状态、重传和密钥依赖显著增加，难以由层链表达|未选；若 G-NATT-1 要求端到端协商再立项|

### 14.3 D3 依赖与错误处理

依赖顺序为 `ip → udp → ike_nat_t`；`ike_nat_t` 依赖 UDP 端口和 IP 四元组才能计算 NAT-D。缺配置、非法 IP、非法 direction/exchange、nonce 长度不符、负 retransmit 或 backoff 小于 1 时，validator 返回 task error，停止该策略，不重试；生成器拒绝 nil config/EmitMsg。重传由配置的 timeout/max/backoff 驱动，达到上限后结束并返回错误；具体默认时长以 `applyDefaults` 为准，不在文档硬编码。

### 14.4 D4 性能与双路验收

路径是 channel 流式逐消息发送，不聚合全部 dialog；内存为每条待发送消息及有界 channel，CPU 主要用于 SHA-1 NAT-D 与 header/payload 编码。目标吞吐、并发流数、最大报文、缓冲上限和 CPU 并行度尚无基准，标 G-NATT-6 待确认，不作承诺。验收需分别：① pcap 路径用 tshark 校验 SPI、exchange、marker、长度、帧数；② NIC 路径用 tcpdump 校验同一字段，并对比 pcap/NIC 包数、吞吐、延迟、队列积压和丢包。基线、目标规模、压力上限、长时间、并发交错、背压六类场景均列入 G-NATT-6。

### 14.5 D5 八要素

|要素|定稿|
|---|---|
|文件|`internal/protocol/ike_nat_t/{planner.go,layer_gen.go}`；本文三份权威产物|
|接口|`IKENATTGenerator.Generate`、planner `Plan`/`Generate`|
|结构|`[ip,udp,ike_nat_t]`；业务字段在终结层，数量在 `flow_control`|
|流程|验证→建 channel→按 dialog 编码→Emit→关闭|
|错误|验证失败传播 task error；不以 0 包成功代替|
|性能边界|流式单消息；规模基准列 G-NATT-6|
|冲突点|4500 marker 与 UDP-ESP/keepalive 的 payload 形状不可混淆；方向不能重复交换|
|回滚|只回滚本次三文件改动，恢复上一版本层链 JSON 与文档，不改代码|

### 14.6 D6 动态字段清单

|字段|策略/序号算法|证据或状态|
|---|---|---|
|`ip.src`/`ip.dst`|fixed；多流动态待补 `inc/rand/list/pattern`|公共层，G-NATT-5|
|`udp.src_port`/`udp.dst_port`|fixed；4500 由 NAT detected/PortFloat 分支|`planner.go:688-735`|
|Initiator/Responder SPI|运行随机非零/响应零或 dialog 学习；按消息序号取对应 SA|`planner.go:217-233,828-856`|
|message direction/exchange/message_id|按 `dialog` 索引顺序|`types.go:4589-4621`|
|NAT-D hash|SHA-1 四元组+SPI 输入，20B|`planner.go:688-735,839-856`|
|业务 payload/nonce|配置 fixed；nonce 长度 validator 校验|`encodeNATTPayloads:911-1042`|
|marker/ESP/keepalive|由 NAT/端口/子流事件决定|`runPlan`、`emitESPSubFlows`、`emitKeepaliveSubFlows`|
|retransmit timeout/backoff|按配置递增/上限截断|`applyDefaults:654-686`|

开工范围的动态策略只声明已落码的 SPI/NAT-D/重传算法；其余五策略矩阵在 G-NATT-5 代码接线后新增用例。`flow_control.flows=N` 是数量，不替代动态字段；无动态四元组的多流必须拒绝或先补代码。

### 14.7 D7 门1三行对照

- **§1**：旧 `count`、`dst_port`、顶层 `ike_nat_t` 均为零残留；本例完整形状见 §1，地址/端口/业务分别进入 `ip`/`udp`/`ike_nat_t`。
- **§3**：会话表=一条 IKE SA；事务=SA_INIT header-only；关联=SPIi/SPIr+MessageID；插入=UDP payload（4500 marker 在 IKE 前）；时间线=dialog 顺序。当前单消息 case 不覆盖完整协商，扩展列 G-NATT-1。
- **§12**：四元组、SPI、NAT-D、message、marker/ESP/keepalive、重传逐项见 §14.6；序号位置见对应代码行。

### 14.8 D8 状态

当前层链改造已完成，旧顶层字段零残留。未覆盖的 NAT-D/4500/ESP/keepalive/重传与负例均已登记 G-NATT-1 并有 P3/P4 扩展计划；性能基准登记 G-NATT-6；动态五策略接线登记 G-NATT-5。不得将这些计划描述为现有能力。

## 15. 六项测试审计（T1-T6，2026-10-01）

| ID | 审计结论 | 证据 |
|---|---|---|
| T1 | 1 个 ID 唯一、顺序与 JSON 一致且 JSON 可解析 | `cases/ike_nat_t.json` 机读审计 |
| T2 | 唯一正例采用严格 `[ip,udp,ike_nat_t]` 层链；`ike_nat_t` 为 UDP 终结层 | `spec_json.layers` 与 registry 形状核对 |
| T3 | 当前无负例；不能把 planner 的未入 JSON 拒绝分支宣称为覆盖 | JSON 无 `expect_error` 项；G-NATT-1 |
| T4 | 地址只在 `ip` 层、端口只在 `udp` 层、业务只在 `ike_nat_t` 层；正例无游离旧键 | 顶层键与层内字段审计 |
| T5 | 动态 SPI 只由 `nonzero`/零值断言，未把随机值写死；数量不伪装成业务字段 | testcase §3；JSON fields |
| T6 | 层链迁移不改变 header 字段、帧 offset/hex 或缺口语义；本车道未跑 suite/MCP/NIC | 设计 §7、testcase §10；工作流约束 |

**迁移状态**：1/1 case 已为目标层链；没有故意保留的 presence 混用正例。若新增 presence 负例，必须使用“层链 + 顶层 `ike_nat_t:{}` 并存”的判死形状；不得把缺少业务层或普通未知键误当 presence 覆盖。未知层拒绝的真实代码锚词必须是 `unknown layer`，但当前 JSON 未登记该负例，故不计入 T3。

## 16. 六项覆盖清单（C1-C6）

| ID | 覆盖要求 | 当前结论 |
|---|---|---|
| C1 | IPv4 UDP 500 上 IKEv2 SA_INIT header-only | 已覆盖 `ike_nat_t_sa_init_header_only` |
| C2 | IKE header 字段、动态 SPI 与稳定帧字节 | 已覆盖 version/exchange/flags/length、SPIi/SPIr、offset 58 |
| C3 | 4500 marker、NAT-D 与端口浮动 | 未覆盖，G-NATT-1；500 例不能推导 4500 行为 |
| C4 | ESP-in-UDP、keepalive、重传 | 未覆盖，G-NATT-1；实现分支不等于 case 覆盖 |
| C5 | 错误处理与 presence/unknown-layer 判死形状 | 当前无负例，G-NATT-1；真实未知层锚词为 `unknown layer` |
| C6 | pcap/NIC 双通道与全量实际流程校准 | 文档车道未运行 suite/MCP/NIC，不宣称通过；待 P5/P6 |

## 17. 修订记录

- v1.1.0（2026-09-30）：迁移唯一 case 至 `[ip,udp,ike_nat_t]` 严格层链；补齐 D1–D8、三张子表、三路对照、候选方案、动态字段与性能双路验收；自审 2 轮，末轮干净。
- v1.0.1（2026-09-29）：批次二门1补齐 §1 逐键去向/目标形状、§1–§14 十四行表、五层与五件套、产物过期 G-NATT-2、框架缺口 G-NATT-4/5、反查红项；旧层链问题已在 v1.1.0 迁移关闭。
- v1.0.0（2026-09-29）：按现有实现与 `ike_nat_t.json` 建立 as-built 文档。
