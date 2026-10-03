# IKE 设计契约（文档阶段 as-built）

> 版本：v1.1.4；日期：2026-10-01；协议：`ike`；权威用例：`trafficgen/test/protocol_pcap/cases/ike.json`。
> 唯一正例保持顶层仅 `layers` 的 `udp(src_port=12345,dst_port=500) → ike` 形状；`ike` 仍是空壳层：registry 有 UDP terminal 和端口契约，但 `fields` 为空，层链 translate 也未把 `layers[].ike` 写入 `spec.IKE`，因此不宣称运行时层链通过。

## D1 范围、规范和边界

规范基线：RFC 7296 §1.2、§2.4、§3.1–§3.2；RFC 7383（IKEv2 fragmentation）；RFC 4303（ESP）；RFC 5998（EAP）；RFC 8229（IKE over TCP）。当前可由 IKE planner 生成 standard_v2、IKEv1、rekey、DPD、delete、informational、EAP、ESP opaque 和 SKF 分支，但权威 cases 只有 standard_v2 空配置四包。真实密码学、证书验证、IKE over TCP、NAT-T 4500 不属于本 `ike` 层承诺，NAT-T 另有 `ike_nat_t`。IKE 业务配置由 legacy planner 的 `spec.IKE` 消费；在层链路径中，空壳 `ike` 配置尚未翻译到该字段。

## D2 层链唯一真相与空壳例外

**层链样例（当前唯一正例的完整配置形状）**：

```json
{"layers":[{"udp":{"src_port":12345,"dst_port":500}},{"ike":{}}]}
```

地址只住 `ip`，端口只住 `udp`，数量只住 `flow_control`。当前 `registry.go:532-535` 已注册 `ike` 为 UDP terminal，但没有 `Fields`；`chain_planner_translate.go` 的 `translateTerminalConfig` 仍没有 `case "ike"`，所以空层配置尚不能承载 `IKEConfig`。当前 cases 已迁成上述目标形状，但必须先完成代码接线再宣称运行时可执行。

### 旧键逐项去向

| 键 | 存量 | 目标去向 | 当前处置 |
|---|---:|---|---|
| `src_port` | 1 | `layers[].udp.src_port` | 已迁移；仍待代码接线后的真实执行验证 |
| `dst_port` | 0 | `layers[].udp.dst_port` | 已补显式默认 500；仍待真实执行验证 |
| `src_ip`/`dst_ip` | 0 | `layers[].ip.src/dst` | 未出现，继续由公共地址默认 |
| `count` | 0 | `flow_control` | 未出现 |
| 顶层 `ike` | 1 | `layers[].ike` 的字段映射 | 已迁移为空终结层；仍待代码接线后的真实执行验证 |

## D3 线格式、字段和偏移

IKE header 固定 28 字节，网络字节序：`SPIi(8)|SPIr(8)|NextPayload(1)|Version(1)|ExchangeType(1)|Flags(1)|MessageID(4)|Length(4)`（RFC 7296 §3.1）。无 VLAN、IP options 时，IPv4 下 IKE 起点为 Ethernet 14 + IPv4 20 + UDP 8 = 42；IPv6 外层起点为 62。UDP 目的端口默认 500；planner 拒绝目的端口非 0/500，并拒绝源端口 500（`planner.go:172-191`）。

standard_v2 的顺序是 `IKE_SA_INIT request/response`（exchange 34）再 `IKE_AUTH request/response`（exchange 35）；Initiator flag=0x08，Responder flag=0x20，Version=0x20（major 2/minor 0）。payload 通用头为 NextPayload/Critical/Reserved/Length（RFC 7296 §3.2）。SPI、Nonce、KE、AUTH、MessageID、Length 和 ESP/SKF 字段都是动态输出，算法位置见 `planner.go:815-861,1021-1069,1088-1119,1310-1480,1552-1619,1657-1825`。

## D4 会话、事务和业务面

| 项 | 当前实现 | 当前用例 |
|---|---|---|
| 会话 | 一个 IKE SA；SPIi/SPIr 关联消息 | 1 个默认 SA |
| 事务 | SA_INIT req/resp → IKE_AUTH req/resp | 四消息、四 datagram |
| 关联 | SPI 在 SA 内保持；MessageID 按交换递进 | 动态 SPI 不固定断言 |
| 插入位置 | UDP 终结层 payload | `[udp, ike]` 目标链 |
| 时间线 | planner channel 逐消息 yield；不等待真实响应 | 顺序四包 |

无长连接 TCP 载体；因此 `sessions[]` 不适用，但同一 SA 的多事务、异常结束和长保活仍须在后续 cases 中单独登记。ESP 数据面和重钥是同一 SA 的扩展，不是重复冒烟包。

## D5 P1 规范矩阵

| 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|
| UDP 500、临时源端口（RFC 7296 §1.2） | 客户端 SA | `planner.go:172-191` | 当前 case 仅 12345→500 |
| IKE header（§3.1） | v2 四消息 | `buildIKEMessageBytes:1021-1069` | 已有正例；IPv6/边界待补 |
| payload chain（§3.2） | SA/KE/Nonce/Auth | `encodePayloads:1088-1119` | 未逐 payload 覆盖 |
| SA_INIT/AUTH（§2.4） | 标准建 SA | `buildStandardV2:1974-2027` | 仅一条正例 |
| fragmentation（RFC 7383） | SKF 大 AUTH | `shouldFragment:907-910` 等 | 未入 cases |
| ESP（RFC 4303） | opaque 数据面 | `emitESPDataPlane:1657-1825` | 未入 cases |
| EAP（RFC 5998） | EAP 认证 | planner scenario 分支 | 未入 cases |
| TCP（RFC 8229） | IKE over TCP | planner 明确拒绝 | 明确不支持 |

## D6 三路对照与方案选择

规范原文决定字段和交换顺序；本仓 planner/test 决定已实现 wire 形状；商业设备和独立开源实现的线字节尚未取证，不能写成已确认现网行为。

| 方案 | 取舍 | 结论 |
|---|---|---|
| A：IKE 作为 UDP terminal，复用 legacy Planner | 保持已有字节和校验逻辑；需要补层配置翻译 | 采用，当前 `layer_gen.go:34-80` 已按此生成 |
| B：把每个 IKE payload 拆成独立层 | 字段可细分，但破坏一个 UDP datagram 内 payload chain，接线复杂 | 不采用 |
| C：保留 flat `spec.IKE` 永久入口 | 兼容现状，但违反层链唯一真相、无法与策略层统一 | 仅作过渡，不作为目标 |

## D7 性能、输出和错误

planner 通过 channel 逐消息生成，generator 逐消息转成 `MessageEvent`，不聚合整个会话（`planner.go:Plan`、`layer_gen.go:56-80`）。当前无吞吐、并发、内存基准，不写承诺数字。验收必须使用同一 cases JSON 同时覆盖 PCAP 与 NIC；PCAP 断言 tshark `isakmp.*`、UDP 字段和 raw offset，NIC 由 tcpdump 复用同一字段/帧断言并记录 checksum offload 边界。

validator 在输出前拒绝：缺 IKE、非法 IP、目的端口非 0/500、源端口 500、未知 scenario、Scenario 与 Messages 冲突、坏 proposal/nonce/payload/ESP、非法 encrypt mode；`Generate` 对 nil EmitMsg/config 和 context cancellation 返回错误。失败必须传播 task error，不得 completed/0 packet 假成功。

## D8 接口、冲突点和回滚

当前接口：`IKEGenerator.Generate(ctx,*layers.GenRequest) error`（`layer_gen.go:36`）、`GenEvents()`、`Planner.Validate`、`Planner.Plan`。生成器直接读取 `req.Meta.IKE`，因为 translate 无 IKE case；这正是层链迁移的阻塞点。

代码阶段需新增 registry `Fields`、`translateTerminalConfig` 的 IKE 映射、schema 生成物和严格层链端到端验证；保持 `IKEConfig` 字段的唯一消费权。若接线失败，回滚 registry/translate/schema 接线，恢复当前 flat 过渡 cases；不得删除已有 planner。

## D1–D8 完成状态与缺口

| ID | 结论 | 证据/迁入计划 |
|---|---|---|
| D1 | 范围和 RFC 边界已定 | 本节；高级分支逐项登记 |
| D2 | 目标层链已定，存量正例已迁 | `cases/ike.json` 顶层仅 `{layers}`；registry 无 Fields、translate 无 case；代码阶段补齐后迁移验证 |
| D3 | header/payload/动态字段已列 | `planner.go` 对应位置；逐字段 cases 待补 |
| D4 | 四件套已展开 | 本文 D4；多 SA/异常/保活待补 |
| D5 | 八项矩阵已列 | 本文 D5 |
| D6 | 三路结论和方案对比已列 | 本文 D6；第三源待确认 |
| D7 | 流式路径和双输出契约已定 | 本文 D7；无实测性能数字 |
| D8 | 接口、冲突、回滚已定 | 本文 D8 |

### 缺口登记

| 缺口 | 现象 | 证据 | 归属阶段与计划 |
|---|---|---|---|
| G-IKE-1 | 空壳层无 Fields，业务键不能住层 | `registry.go:533-536`：`ike` 仅注册 `FieldContract`，无 `Fields` | 代码阶段：补 Fields/schema |
| G-IKE-2 | translate 无 `ike` 分支，`spec.IKE` 不从层链配置得到 | `chain_planner_translate.go` 的 `translateTerminalConfig` 当前终结层翻译分支无 `ike`；`strategy_convert.go:1181-1184` 的 flat 解析不等于层链接线 | 代码阶段：补 terminal translation |
| G-IKE-3 | 存量正例已迁为 `{layers}`，但层链仍不可执行 | `cases/ike.json` 已为 `layers`; registry 有注册但 `translateTerminalConfig` 无 `case "ike"` | 代码阶段补 terminal translation/Fields；完成端到端验证后关闭阻塞 |
| G-IKE-4 | 负例为 0，高级 scenario/ESP/SKF/IPv6 未由 cases 驱动 | JSON 仅 1 正例 | 测试阶段：逐分支补负例和边界例 |
| G-IKE-5 | 动态业务字段无 ike allowlist | `layer_dyn.go` 无 ike 行 | 框架/代码阶段：先定字段语义再补动态覆盖 |
| G-IKE-6 | 历史 pcap/结果未作为今日复跑证据 | 现有结果产物无本次复跑记录 | P5：真实 MCP→pcap/NIC→tshark 重跑 |
| G-IKE-7 | 商业/独立开源第三源未取证 | 当前仅 RFC+本仓实现 | 待确认：授权设备抓包或核对 Linux 实现 |

## 门1 §1–§14 对照表

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 | 目标层链已定；唯一正例已迁为层链，但 registry/translate 接线缺口仍阻塞运行时验证 | D2/G-IKE-1/G-IKE-2/G-IKE-3 |
| §2 | 策略为单 IKE 模板，任务负责多策略和总量 | D2 |
| §3 | 单 SA、四事务、SPI 关联、UDP payload、顺序 yield | D4 |
| §4 | RFC 7296/7383/4303/5998/8229 矩阵 | D1/D5 |
| §5 | UDP 依赖、validator 错误、task error 传播 | D7/D8 |
| §6 | channel 流式；吞吐数字待实测；PCAP/NIC 双路 | D7 |
| §7 | design/testcase/cases 三件套 | 文件路径与 testcase §1 |
| §8 | 先记录接线计划，再代码阶段改实现 | D8 |
| §9 | RFC+设计+真实 tshark 三源；当前仅 1 正例 | testcase §2 |
| §10 | 本文自审；独立复审另行执行 | 修订记录 |
| §11 | 白话结论见文首 | 文首 |
| §12 | 四元组和业务动态字段逐项登记 | D3；G-IKE-5 |
| §13 | registry 已注册但 schema Fields 未完成 | D8/G-IKE-1 |
| §14 | MCP→引擎→tshark 真实流程为 P5 必做 | D7/G-IKE-6 |

## 修订记录

- v1.1.4（2026-10-01）：按当前 registry/translate/JSON 重新对账；确认 `ike` registry 仍为 UDP terminal、FieldContract 仅约束 `udp.dst_port=500` 且 `fields` 为空，`translateTerminalConfig` 无 `ike` 分支；明确空壳例外、G-IKE 证据与未运行边界；自审两轮，末轮干净。

- v1.1.3（2026-10-01）：第二轮实现对账确认 IKE registry 只有 UDP terminal/端口契约，没有 Fields，`translateTerminalConfig` 也没有 `ike` 分支；补充空壳例外和 legacy flat 解析与层链接线的区别，更新 G-IKE-1/G-IKE-2 证据；自审两轮，末轮干净。
- v1.1.2（2026-10-01）：补齐 D2 的完整层链样例与存量迁移事实；唯一正例明确为 `udp(src_port=12345,dst_port=500) → ike`，保留 Fields/translate 未接线、0 负例和未运行测试的诚实边界；自审两轮，末轮干净。
- v1.1.1（2026-10-01）：复核当前 registry/translate 能力后确认唯一正例已迁为层链，但 IKE Fields/translate 接线仍阻塞运行时验证；同步 G-IKE-3 与 §1 证据；自审两轮，末轮干净。
- v1.1.0（2026-09-30）：按 T1–T6/C1–C6 重写。
