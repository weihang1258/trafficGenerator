# IKE（Internet Key Exchange）设计契约

> 版本：v1.0.0（as-built）；日期：2026-09-29；协议名：`ike`；权威用例：`trafficgen/test/protocol_pcap/cases/ike.json`。
> 本文逆向记录当前 Go planner/layer generator 与唯一现存 PCAP case，不把未实现能力写成承诺。

## 1. 范围与配置真相

IKE 是 UDP 终结层，承载 IKEv1/v2 密钥交换及可选 opaque ESP 数据面。当前实现入口为 `trafficgen/internal/protocol/ike/planner.go`、`layer_gen.go`；实现已注册为 `udp` 依赖的终结层，但现存权威 case 仍是 legacy flat 形状（`src_port` + `ike`）；具体业务参数由 `spec.IKE` 传给终结生成器，不能把层链目标形状冒充存量事实。`IKEConfig` 字段以 `trafficgen/internal/core/types.go:4159` 为准。

旧顶层键审计（§1 强制展开，逐键去向；存量实测 `cases/ike.json` **1 例顶层键 = `{src_port, ike}`，属扁平残留，非纯层链形**——迁移未完成，缺口 G-IKE-3）：

| 旧键 | 存量出现 | 去向 |
|---|---|---|
| `src_port` | 1/1 | 公共 FlowSpec transport；目标形迁 `layers[0].udp.src_port` |
| `ike` | 1/1 | `spec.IKE`；目标形迁 `layers[1].ike` |
| `dst_ip`/`dst_port`/`count` | 0 | case 未用（dst 500 走 FieldContract/Validate 默认；count 走 flow_control） |

目标形状（层链完整 spec_json 例子；**存量尚未迁移，此为目标形非存量事实**）：

```json
{"layers":[{"udp":{"src_port":12345,"dst_port":500}},{"ike":{}}]}
```

不存在 `IKEConfig` 以外的协议配置键；本 case 不使用 `src_ip`/`dst_ip`，由公共地址层补默认值。`ike` 层注册为 UDP terminal、依赖 `udp`、目的端口契约 500（`internal/core/layers/registry.go:532-535`）。

## 2. 协议栈、端口与偏移

线序为 Ethernet → IPv4/IPv6 → UDP → IKE。默认目的端口 500（RFC 7296 §1.2）；planner 拒绝目的端口非 0/500，并拒绝源端口 500，客户端使用显式临时端口 12345。无 VLAN、IPv4 options 时 IKE header 起点为 42（14+20+8），固定 28 字节（RFC 7296 §3.1）。本 case 的四个 UDP datagram 分别是 SA_INIT request/response、IKE_AUTH request/response。

## 3. 线格式与业务字段

IKE header 为 `SPIi(8)|SPIr(8)|NextPayload(1)|Version(1)|ExchangeType(1)|Flags(1)|MessageID(4)|Length(4)`，网络字节序；v2 为 `0x20`，SA_INIT=34、AUTH=35，Initiator=0x08、Responder=0x20。默认 standard_v2 模板生成 SA、KE、Nonce 与 AUTH 所需 payload；payload 通用头为 NextPayload/critical/reserved/length（RFC 7296 §3.2）。密码学未实现，SK/SKF 使用由 `OpaqueKeySeed` 派生的确定性伪字节。

动态字段清单（生成算法/位置）：① SPIi/SPIr，按 `deriveSPI`/`opaqueRNG`（`planner.go:815-861`）生成并在 SA 内保持；② Nonce、KE、AUTH/opaque bytes，按 `encodeKE`、`encodeAuth`、`encodeSK`（`planner.go:1310-1480`）生成；③ MessageID，按消息序列从 `StartMessageID` 递进（`planner.go:1552-1619`）；④ header Length，由 `buildIKEMessageBytes`（`planner.go:1021-1069`）回填；⑤ ESP SPI/sequence/IV/ICV（可选），由 `emitESPDataPlane`/`buildESPPacket`（`planner.go:1657-1825`）生成。业务字段逐个覆盖：Role、Scenario、Messages、DefaultProposal、DefaultDHGroup、DefaultNonceSize、DefaultAuthMethod、EAPOnly、ChildSAs、ESPDataPlane、FragmentationSupported/Threshold、EncryptMode、Strict/FaultInjection，均由 `IKEConfig` 读取；当前唯一 case 只使用默认 scenario。

## 4. 五层覆盖

- 功能层：SA_INIT 与 IKE_AUTH 双向四消息；交换类型和角色 flags 可观察。
- 性能层：每个 IKE 消息一个 UDP packet；无 TCP 握手、无内部聚合；可选 SKF/ESP 扩展受 60,000B opaque 上限与流式 planner 约束。
- 数据层：28B header、payload chain、SA/KE/Nonce/Auth 长度与 checksum/长度回填；case 固定长度 376/225。
- 地址与流层：UDP 四元组，dst=500，src=12345；上下行由 Message.Direction 映射，generator 设 `L4PortOverride=true`（`layer_gen.go:66-74`）。
- 业务层：IKE SA 建立后认证；本 case 不宣称真实密码学，仅验证 standard_v2 wire 形状。

## 5. 会话、事务和时间线

单 IKE SA 会话：SA_INIT request → response → IKE_AUTH request → response；SPIi 在会话内关联所有消息，Message ID 按交换递进。事务序列和方向来自 `buildStandardV2`（`planner.go:1974-2027`）。插入位置为 UDP packet payload；时间间隔由公共调度层提供，协议 planner 不等待真实响应。ESP/重钥/重传等分支未由现存 case 覆盖。

## 6. 性能设计与验收

planner 返回 channel，按消息逐个 yield；layer generator 逐事件转发（`layer_gen.go:34-80`），不聚合全部消息。UDP 无连接控制包；目标是每个业务消息一 datagram，长度受 IKE fragmentation 规则约束。当前性能验收只可确认流式、固定四包和无 TCP 控制包；吞吐/时延基准不在本 case。

## 7. 错误处理

validator 在 `planner.go:172-275` 执行边界检查：缺失 IKE、非法 IP、dst 非 500、src=500、未知 scenario、Scenario 与 Messages 同时设置、非法加密模式、坏 payload/nonce/proposal/ESP 配置均返回错误；`Generate` 对 nil EmitMsg/config 返回错误（`layer_gen.go:36-43`），上下文取消传播。错误不得静默产出 0 包。

## 8. 边界与不适用项

IKE over TCP（RFC 8229）、NAT-T 4500、真实加密、证书验证、服务端状态机和实际 ESP 解密不属于 `ike` 当前实现；NAT-T 另见 `142-ike_nat_t-*`。IPv6 outer、VLAN、fragmented_auth、IKEv1 等虽有 planner 分支，但无本权威 case 证据，不能申报覆盖。

## 9. 原子 ID 与完成定义

唯一 ID 仅 `ike_smoke_01`（1 正，0 负），与 cases JSON 顺序一致。完成定义：生成 4 包；packet 1 dstport=500、v2、SA_INIT、initiator、length=376；packet 2 SA_INIT responder；packet 3/4 AUTH、对应 flags、length=225；动态 SPI 只作存在性/不固定断言。

## 10. 规范矩阵

|规范要求|业务场景|代码现状|缺口|
|---|---|---|---|
|RFC 7296 §3.1 header|四包 standard_v2|`buildIKEMessageBytes`|无|
|RFC 7296 §3.2 payload|SA_INIT/AUTH|`encodePayloads`|无|
|RFC 7296 §1.2 UDP 500|四元组|Validate + registry|无|
|RFC 7296 §2.4 exchange|SA_INIT/AUTH|`buildStandardV2`|无|
|RFC 7383 fragmentation|大 AUTH 分支|planner 有 SKF|本 case 未覆盖|
|RFC 4303 ESP|可选数据面|`emitESPDataPlane`|本 case 未覆盖|
|RFC 5998 EAP|EAP scenario|planner 有分支|本 case 未覆盖|
|RFC 8229 TCP|不适用|明确拒绝|G-IKE-1|

## 11. 代码设计与接线

`Planner.Validate/Plan` 完成校验和 packet channel 规划；`IKEGenerator.Generate` 构造 FlowSpec，复用 legacy planner，并将每个 PacketConfig 转为 MessageEvent；注册点为 `layer_gen.go:105-112`，registry 为 `registry.go:532-535`，strategy conversion 为 `internal/core/strategy_convert.go:1181-1184`。UDP 层负责外层头与统一序号/IPID/Timestamp；IKE 仅产出 L7 bytes。

## 12. 门1 §1–§14 十四行对照表

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 旧键逐键去向 + 目标形状见 §1 强制展开；**存量 1/1 例仍是扁平残留形（`src_port`+`ike` 顶层键），未达纯层链形**，迁移列为 G-IKE-3，不冒充已迁移 | §1；`cases/ike.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 ike 流量模板（`ike` 键住 `spec.IKE`）；任务 = 多策略合跑 + 总量封顶，框架语义未动 | 设计 §1/§11 |
| §3 五件套 | 会话表 = 单 IKE SA（§5）；事务序列 = SA_INIT req/resp + IKE_AUTH req/resp 四事务（§5）；关联关系 = SPIi 全程不变 + MessageID 递进（§3/§5）；插入位置 = udp 层 payload（终结层，§11）；时间线 = dialog/planner 顺序 yield（§5/§6）。UDP 无长连接载体，`sessions[]` 不豁免问题不适用（无会话数组） | §5/§11 |
| §4 查规范 | RFC 7296 §1.2/§3.1/§3.2/§2.4 + RFC 7383 + RFC 4303 + RFC 8229（拒绝项）逐条对照，矩阵见 §10 | §10 |
| §5 依赖与错误 | `DependsOn ["udp"]`（`registry.go:532-535`）；拒绝分支见 §7（dst 非 0/500、src=500、缺 IKE、未知 scenario、Scenario+Messages 冲突、坏 payload 等）；错误传 task error，不产 0 包假成功 | §7/§11 |
| §6 性能 | 见 §6（channel 流式逐消息 yield、每消息一 datagram、60,000B opaque 上界；吞吐数字本 case 无基准，不写承诺；pcap/NIC 双输出契约明写 §1/testcase §1） | §6 |
| §7 三份文档 | `143-ike-design.md` + `143-ike-testcase.md` + `cases/ike.json` 三件套，ID/包数/断言三方一致 | testcase §2/§5 |
| §8 设计先行 | as-built 文档先行定稿于 P4 代码阶段之前；后续改动以本文为唯一入口 | 修订记录 |
| §9 测试三源 | 三源 = RFC 7296（§10 矩阵）+ 本设计契约（§11）+ tshark 3.6.14 `isakmp.*` 字段与 case 断言（testcase §1/§3，字段名机读实测存在）；1 ID 逐项回指 testcase §2；存量审计 testcase §8 | testcase §2/§5/§8 |
| §10 评审闭环 | 车道内机读对账自审（§16 修订记录）；对抗复审由主线程另行派发，本文不代审 | §16 |
| §11 白话 | 每阶段白话一句（见文档首部白话与各节首句） | 全文 |
| §12 动态字段清单 | 四元组（src/dst IP、src/dst port）+ 业务字段（SPIi/SPIr、Nonce、KE、AUTH、MessageID、header Length、ESP SPI/seq/IV/ICV）逐个列算法与代码位置，见 §3 动态字段清单 | §3 |
| §13 schema 派生 | `ike` 已注册 `registry.go:532`（**不新增层**，无独立 Fields——层条目零负载，配置经 spec.IKE flat 键携带，registry 注释明写）；改 Fields 须重跑 schemagen | §11 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `isakmp.*` + frames 双通道断言；pcap 与 NIC 共用同一 cases JSON 断言集（testcase §1）；结果产物过期登记 G-IKE-2 | testcase §1/§8 |

## 13. P3 对接清单

注册 validator/generator；确认 layer chain 只含 UDP 与 IKE；核对字段名 `isakmp.*` 与 tshark 版本；运行 JSON parser、packet count、字段和 frame offset 检查。

## 14. 缺口登记（三要素：现象/证据/归属阶段）

|ID|现象|证据|归属阶段|
|---|---|---|---|
|G-IKE-1|负例零覆盖与高级分支（NAT-T/TCP/ESP/EAP/分片/IKEv1/IPv6/VLAN）无用例——validator 拒绝分支虽已实现但未被 JSON 驱动，不得申报已覆盖|`cases/ike.json` 仅 1 正例 0 负例（机读实测）；`planner.go:184-232` 拒绝分支在码|P3/P4 用例扩展|
|G-IKE-2|结果产物过期：`trafficgen/docs/protocol-pcap-test/ike.md`（tracked，`git ls-files` 可证）写 "pass 1"，末次提交 `e7e7d1c`（2026-08-27）**早于判死提交 `0417be5`（2026-09-13 扁平判死）**；`protocol-pcap-test/ike/` 目录不存在（0 个 pcap 留档）。**该 1/1 pass 未经今日复跑证实，不得作为"今日已复跑"依据**（口径同 pcep G-PCEP-11）。且存量 case 本身是扁平残留形，判死后今日能否通过待复跑裁定——两个事实叠加，归 P5 重跑裁定|`git log -1 -- trafficgen/docs/protocol-pcap-test/ike.md` = `e7e7d1c` 2026-08-27；`ls protocol-pcap-test/ike/` 不存在|P5（重跑套件后重生成产物）|
|G-IKE-3|存量 case 形状违规：`ike_smoke_01` 顶层键 = `{src_port, ike}`（扁平残留），未达纯层链形 `{layers}`；按顶层白名单口径属待迁移形状，判死风险由复跑裁定，本文档如实记形不冒充合规|`cases/ike.json` 机读：`spec_json` 顶层键恰为 `src_port`、`ike`，无 `layers`|P4（cases 迁移）|
|G-IKE-4|`CheckProtoFlat` 无 `ike` 分支（`grep -c 'protocol == "ike"' strategy_convert.go` = 0 实测）：顶层 `ike` 子映射 presence 今日不判死，presence 负例今日建了会真绿 = 假通过，**不建**（等框架级 unknown-key 白名单，禁单协议黑名单分支，kingbase 记忆裁定）|`strategy_convert.go` grep 实测 0 命中|P6 框架面|
|G-IKE-5|动态字段 allowlist 无 `ike` 行（`internal/core/layer_dyn.go` 头部 grep 实测 0 命中）：业务字段动态对象即拒；四元组 `ip`/`udp` 全开。业务字段动态（SPI/Nonce/MessageID 五策略）今日不可用|`layer_dyn.go` grep 实测|P6 框架面|

## 15. 覆盖反查门建议断言行（供主线程登记 `coverage_gate.py`；本车道不碰该文件）

每条均可从 `cases/ike.json` 与本契约静态机读判定：

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases['ike']) == 1` 且 ID 集合 = `{ike_smoke_01}`，顺序一致 | testcase §2 |
| 2 | `ike_smoke_01.expect.packet_count == 4` | testcase §3 |
| 3 | packet 1/3 `exchangetype` = 34/35；packet 1/3 `flags` = `0x08`；packet 2/4 `flags` = `0x20` | testcase §3 |
| 4 | `isakmp.length`：packet 1 = 376、packet 3/4 = 225 | testcase §3 |
| 5 | packet 1 `udp.dstport = 500`、`mjver = 0x02`、`mnver = 0x00` | testcase §3 |
| 6 | 层链迁移完成后：`spec_json` 顶层键 ⊆ `{layers}`（**今日不成立——存量为 `{src_port, ike}`，红项如实标红，不得申报"今日已过"**） | 设计 §1/G-IKE-3 |

## 16. 修订记录

- v1.0.1（2026-09-29）：按批次二 as-built 门1要求补齐 §1 旧键逐键去向与目标形状、§1–§14 十四行表、五层与五件套展开、存量扁平形状 G-IKE-3、结果产物过期 G-IKE-2、presence/dynamic 框架缺口 G-IKE-4/5、§15 反查建议；**自审 2 轮，末轮干净**。
- v1.0.0（2026-09-29）：按现有实现与 `ike.json` 建立 as-built 文档。
