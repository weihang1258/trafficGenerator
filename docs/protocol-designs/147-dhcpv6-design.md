# DHCPv6（RFC 8415）设计契约

> 编号 #147；as-built 文档轨版本 v1.0（2026-09-29）。依据 RFC 8415 §§6–7、11、15–21，现有 `trafficgen/internal/protocol/dhcpv6/` 实现、registry/strategy_convert 接线及 `cases/dhcpv6.json`。本协议是 IPv6/UDP 终结层；本文描述已实现能力，不把未实现能力冒充完成。

## 1. 范围、形状与实现状态

支持 DHCPv6 client/server 消息 1–11、relay-forward/relay-reply 12/13；每条消息输出一个 UDP datagram。手工 `messages[]` 按声明顺序回放；`scenario` 自动编排 `sarr`、`sarr_rapid`、`renew`、`rebind`、`release`、`decline`、`confirm`、`information_request`、`reconfigure`、`relay`。IPv4 被拒绝；默认 TTL=64；默认端口方向为 client 546、server 547。

层链目标形状为顶层仅 `layers`；现有唯一 case 仍保留 `src_ip`、`dst_ip`、`src_mac`、顶层 `dhcpv6`，因此不满足层链唯一真相，属于 G-DHCPV6-1，本文不改 JSON。目标形状样例（改写示例，键名对齐 registry 的 `eth.src_mac`/`ip.src/dst` schema，P4 重钉时以引擎实跑为准）：

```json
{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:ff"}},{"ip":{"src":"2001:db8::1","dst":"2001:db8::2"}},{"udp":{}},{"dhcpv6":{"scenario":"sarr","default_leased_addr":"2001:db8::100"}}]}
```

registry `dhcpv6` 为 `CategoryTerminal`、依赖 `udp`（`internal/core/layers/registry.go:178-180`）；`strategy_convert.go:1170-1175` 解析层内 `dhcpv6`；生成器注册在 `internal/protocol/dhcpv6/layer_gen.go:188-195`。业务动态 allowlist 未为 dhcpv6 开放（G-DHCPV6-2），四元组动态仍由 `ip`/`udp` 层承载。

## 2. 业务场景与五层覆盖（门1 §2/§3 展开见 §3 与本节）

**门1 §2（策略/任务边界）**：策略承载单协议模板；任务负责多策略合并与总量封顶，地址、端口、MAC 仍由层链/通用 flow 形状提供。
| 现网场景 | 编排 | 代码/用例 |
|---|---|---|
| 地址发现与分配 | SOLICIT→ADVERTISE→REQUEST→REPLY | `scenario.go:210-220`；`dhcpv6_smoke_01` |
| 快速提交 | SOLICIT(+RapidCommit)→REPLY | `scenario.go:222-235`；待用例 |
| 续租/重绑定 | RENEW/REBIND→REPLY | `scenario.go:237-268`；待用例 |
| 释放/冲突/换链路 | RELEASE/DECLINE/CONFIRM→REPLY | `scenario.go:270-334`；待用例 |
| 无状态信息 | INFORMATION-REQUEST→REPLY | `scenario.go:336-379`；待用例 |
| 服务端重配置 | RECONFIGURE→RENEW→REPLY | `scenario.go:381-406`；待用例 |
| 中继 | 四个内层消息各包 RELAY-FORW/RELAY-REPL | `scenario.go:408-468`；待用例 |

**功能层**：消息类型 1–13、手工/场景两种驱动、option TLV、DUID、IA_NA/IAADDR、relay 头已实现；当前 JSON 只验证 SARR。错误类覆盖要求包括 IPv4、空消息、非法 msg type、relay 缺字段、hop 越界、option 超 MTU、DUID 错误、缺 MAC、未知 scenario。

**性能层**：每消息一个 datagram；option 总长上限 1452（1500−40−8），DUID 上限 128，relay hop 上限 32；包数与场景消息数线性，单包固定头 4B、relay 固定头 34B。跨 UDP/IPv6 分段不由 DHCPv6 层实现。

**数据层**：TLV code/length/data 均 2/2/variable，整数和 IPv6 地址网络字节序；DUID-LLT/EN/LL 三种；IA_NA、IA_TA、IAADDR、IAPD、IAPREFIX、ORO、StatusCode、DNS wire name、RapidCommit 等 builder 已有；边界/截断/未知 option 尚未形成 case（G-DHCPV6-3）。

**地址与流层**：仅 IPv6；单流为实现基线；up/down 交换 IP、MAC、端口；relay 使用 `RelayConfig` 的 relay IP/MAC，relay 端口恒 547。流关联不适用（无控制流派生数据流）；多流/多会话不适用，配置是单一事件序列。

**业务层**：SARR 已有；其余九类场景、多事务重用 XID、relay 父子关联、跨会话隔离待新增原子用例。保活不适用；DHCPv6 没有连接保活。FIN/RST 不适用（UDP）；异常终止以 planner 错误为边界。

## 3. 线格式与状态/事务

普通消息：`msg-type` 1B + transaction-id 3B + options。每 option：code UInt16 BE + length UInt16 BE + data。Relay：msg-type 1B + hop-count 1B + link-address 16B + peer-address 16B + options；option 9 承载内层消息。实现位置：`planner.go:488-606`（buildMessage/buildClientServerMessage/buildRelayMessage）、`options.go:31-126`（IA_NA/IAADDR/ORO/StatusCode 等 builder）。

状态集合为 `manual` 或场景编排阶段；同一输入确定性地产出结构，但全零 XID和自动 DUID含随机/时间值。场景 SARR 四帧共享同一 XID（`scenario.go:210-220`）；普通 server down 消息复制最近 XID，RECONFIGURE 启动新 XID（`planner.go:369-384`）。

会话五件套：会话表 s1=一条 UDP 流；事务序列 t1=client message，t2=server response，t3=后续同 XID/新 XID 事务，relay 场景为 r1=relay-forward、r2=relay-reply 包装。关联关系是 XID（普通消息）或 option 9 内层消息（relay）；插入位置为 UDP 终结层；时间线严格按 `messages[]`/scenario 返回顺序。无长连接，故保活、FIN、RST 不适用。

## 4. 配置、默认与错误

`DHCPv6Config` 字段定义于 `internal/core/types.go:3877-3947`：messages、scenario、ClientDUID/ServerDUID、RelayConfig，以及 IAID/lifetime/T1/T2/preference/status/ORO/DNS defaults。`DHCPv6Message` 在 `:3949-3967`；RelayFields 在 `:3969-3974`。

流程为层链/转换 → `Planner.Validate`（`planner.go:141-267`）→ `Generate`/`Plan` → `buildMessage` → resolveAddrs → UDP/IPv6/Ethernet。空配置默认单 SOLICIT，但自动 DUID 需要 src_mac。Validate 逐项拒绝：非 IPv6、空 manual messages、msg-type 非 1–13、relay 缺字段/地址非法/hop>32、direction 非 up/down、options>1452、DUID 错、自动 DUID 缺 MAC、relay_config 缺/错 relay IP、未知/冲突 scenario。错误锚词见 testcase §4。

## 5. 动态字段清单（门1 §12 强制展开）

四元组：`ip.src/dst`、`udp.src_port/dst_port`、`eth.src_mac/dst_mac`（registry Fields + layer_dyn allowlist 四层全开）。端口 0 在 dhcpv6 生成器按方向解析为 546/547（`planner.go:443-448`）；链规划器对 dhcpv6 的 0 端口保持 0（`chain_planner.go:920-922`/`1146-1148`），flow 默认源端口 12345（`strategy_convert.go:49` DefaultSrcPort）。序号算法：第 i 条消息 `PacketIndex=i`（`planner.go:398`；链层 `layer_gen.go:135`），逐流四元组由 flow/tuple generator 第 i 流确定性取值。业务字段动态全关：allowlist（`internal/core/layer_dyn.go` layerDynAllowlist）无 `dhcpv6` 行（grep 零命中实测），scenario/messages/DUID/租约地址/options 列表均是结构化对象，对象即 `does not support dynamic`（G-DHCPV6-2）。

## 6. 门1 §1–§14 对照表

| § | 满足方式与证据 |
|---|---|
| §1 | 目标为 layers 链；存量 1 例仍有四个顶层旧键，去向见 §7，G-DHCPV6-1；`cases/dhcpv6.json` |
| §2 | 策略承载单协议模板，任务负责流量总量；strategy_convert:1170 |
| §3 | 五件套见 §3；UDP 单流无保活/FIN/RST，流关联不适用 |
| §4 | RFC 8415 §§6–7,11,15–21；线格式见 §3 |
| §5 | 依赖 UDP；Validate 错误传播见 `planner.go:141-267` |
| §6 | option 1452、DUID 128、hop 32、每消息一 datagram；pcap/NIC 共用 testcase |
| §7 | design + testcase + `cases/dhcpv6.json` 三件套；现有 ID 一致但旧形状缺口 |
| §8 | 本文为实现已落码后的 as-built 契约，未实现项明确为缺口 |
| §9 | RFC/代码/cases/pcap 字段断言四方对照；当前只一条 JSON case |
| §10 | 自审后待独立隔离复审；缺口不得以删除断言消除 |
| §11 | DHCPv6 是 IPv6 上的地址配置消息，client/server 以 XID 配对、relay 以 option 9 包装 |
| §12 | 四元组动态见 §5；业务对象未开放动态 |
| §13 | registry dhcpv6 终结层 + udp 依赖；不新增 schema |
| §14 | pcap/NIC 使用同一 JSON expect；NIC 需 tcpdump 真实捕获，当前未宣称复跑 |

### §1 旧键逐键去向

| 旧键 | 当前例 | 目标去向 |
|---|---:|---|
| src_ip | 1 | `layers[0].ip.src` |
| dst_ip | 1 | `layers[0].ip.dst` |
| src_mac | 1 | `layers[0].eth.src` |
| dst_mac | 0 | `layers[0].eth.dst`（当前由生成器/目标 MAC默认） |
| dhcpv6 | 1 | `layers[1].dhcpv6` |
| count/flow_control | 0 | 任务/策略级 `flow_control` |

## 7. 存量审计、缺口与过期产物

唯一存量 `dhcpv6_smoke_01`：**改写**，保持 SARR 四包与断言，迁移顶层地址/MAC/协议配置到 layers 后重钉；当前不作废、不新增等价覆盖。

| 缺口 | 现象 | 证据 | 归属 |
|---|---|---|---|
| G-DHCPV6-1 | case 顶层旧键与层内配置并存 | `cases/dhcpv6.json` 机读 | P4 层链改写 |
| G-DHCPV6-2 | 业务字段动态未开放 | layer_dyn allowlist 无 dhcpv6 | P4 动态契约 |
| G-DHCPV6-3 | 仅 SARR 一个 case，未覆盖消息/option/错误边界 | JSON 1 ID；planner 分支 1–13 | P3/P4 用例扩展 |
| G-DHCPV6-4 | 结果文档早于 0417be5，数字不可作为今日复跑证据 | `trafficgen/docs/protocol-pcap-test/dhcpv6.md` commit 2026-09-05 | P5 重跑产物 |

过期产物登记：上述 tracked 结果文档末次提交 2026-09-05，早于 2026-09-13 判死提交 `0417be5`；当前车道未跑 pcap/NIC，不引用其中 pass 数字为今日证据。

## 8. 修订记录

v1.0（2026-09-29）：按实现、registry、strategy_convert、唯一 case 与 RFC 8415 写 as-built；登记 G-DHCPV6-1…4。自审 1 轮，末轮干净；待独立审查。
