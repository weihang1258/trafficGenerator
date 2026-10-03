# DHCPv6（RFC 8415）设计契约

> 版本 v1.1（2026-09-30）。本文件按层链配置契约描述现有 DHCPv6 生成器；规范、实现与 cases 三方不一致处列为缺口，不以未验证结果代替证据。

## 1. 范围与严格配置形状

DHCPv6 在 IPv6/UDP 上发送 client/server 消息 1–11 及 relay-forward/relay-reply 12/13；每条消息是一个 UDP datagram。支持手工 `messages[]` 与 `scenario`（`sarr`、`sarr_rapid`、`renew`、`rebind`、`release`、`decline`、`confirm`、`information_request`、`reconfigure`、`relay`）。IPv4 输入拒绝，IPv6 hop limit 默认 64。

严格形状只允许结构性顶层键；地址、端口、MAC、协议业务字段全部进入层链：

```json
{"layers":[{"eth":{"src_mac":"aa:bb:cc:dd:ee:ff"}},{"ip":{"src":"2001:db8::1","dst":"2001:db8::2"}},{"udp":{"src_port":12345,"dst_port":547}},{"dhcpv6":{"scenario":"sarr","default_leased_addr":"2001:db8::100"}}]}
```

`dhcpv6` 的目标形状是 UDP 后的终结层（registry 中虽有 `CategoryTerminal`/`DependsOn: udp` 注册，但当前没有该层 `Fields`，且 `translateTerminalConfig` 没有 `case "dhcpv6"`）。因此本文件和 cases 记录的是目标层链形状，尚不能宣称严格 LayerChain 已可执行；实现入口仍为 `internal/protocol/dhcpv6/layer_gen.go`。业务动态 allowlist 当前没有 DHCPv6 项，故业务对象按静态结构处理；四元组动态由 `ip`、`udp`、`eth` 层承担。缺口 G-DHCPV6-1：补齐 registry `Fields` 与 `translateTerminalConfig` 分支后，才可执行当前层链 cases；缺口 G-DHCPV6-2：若需逐流改变业务字段，须再增加终结层动态契约和序号实现。

## 2. 业务与状态

| 场景 | 消息顺序/编排 | 实现证据 | 用例映射 |
|---|---|---|---|
| 地址发现 | SOLICIT→ADVERTISE→REQUEST→REPLY | `scenario.go:210-220` | `dhcpv6_smoke_01` |
| 快速提交 | SOLICIT（Rapid Commit）→REPLY | `scenario.go:222-235` | G-DHCPV6-3 |
| 续租/重绑定 | RENEW 或 REBIND→REPLY | `scenario.go:237-268` | G-DHCPV6-3 |
| 释放/声明冲突/确认 | RELEASE、DECLINE、CONFIRM→REPLY | `scenario.go:270-334` | G-DHCPV6-3 |
| 无状态信息 | INFORMATION-REQUEST→REPLY | `scenario.go:336-379` | G-DHCPV6-3 |
| 服务端重配置 | RECONFIGURE→RENEW→REPLY | `scenario.go:381-406` | G-DHCPV6-3 |
| 中继 | RELAY-FORW/RELAY-REPL 包装内层消息 | `scenario.go:408-468` | G-DHCPV6-3 |

普通事务由三字节 XID 关联；relay 由 option 9 承载内层消息。当前模型是一条按 `messages[]` 顺序推进的 UDP 流，无连接握手、FIN/RST 或连接保活；同流多轮由 SARR 用例覆盖，非正常结束由 Validate 失败用例覆盖，长保活在 DHCPv6 语义中没有对应动作（G-DHCPV6-3 登记）。

## 3. 线格式与字段

普通消息为 `msg-type(1B) + transaction-id(3B) + options`，因此首个 option 的偏移是 4；每个 option 为 `code(UInt16 BE)+length(UInt16 BE)+data[length]`，总长度为 `4 + Σ(4 + len(data))`。Relay 消息无 transaction-id，固定头为 `msg-type(1B, 12/13) + hop-count(1B) + link-address(16B) + peer-address(16B)`，option 起点为 34，总长度为 `34 + Σ(4 + len(data))`；option 9 的 data 是完整内层 DHCPv6 消息。地址字段按 IPv6 16 字节网络序列化，hop-count 为单字节，最大 32。代码：`planner.go:488-606`、`options.go:31-126`。

消息类型值域按 RFC 8415 §7.3 固定为：1 SOLICIT、2 ADVERTISE、3 REQUEST、4 CONFIRM、5 RENEW、6 REBIND、7 REPLY、8 RELEASE、9 DECLINE、10 RECONFIGURE、11 INFORMATION-REQUEST、12 RELAY-FORW、13 RELAY-REPL。普通消息的 transaction-id 是 24-bit 不透明关联值；同一事务的请求与响应必须复用它，RECONFIGURE 触发的新事务使用新值。生成器对未显式给出的 XID 使用运行期随机值，所以 cases 只能断言存在性或跨包相等，不能钉随机常量。

DUID 编码也属于业务 option 的数据而非 DHCPv6 头：DUID-LLT 为 `duid-type(2B BE=1)+hardware-type(2B BE)+time(4B BE)+link-layer-address(6B Ethernet)`，DUID-EN 为 `duid-type(2B BE=2)+enterprise-number(4B BE)+identifier(variable)`，DUID-LL 为 `duid-type(2B BE=3)+hardware-type(2B BE)+link-layer-address(variable)`；实现将序列化结果限制为 1–128B。客户端/服务端 DUID 分别由 option 1/2 携带，自动 DUID-LLT 依赖 `eth.src_mac`，缺失时 validator 返回 `src_mac is required`。所有 option code/length 和整数数据均为网络字节序；DNS name 使用 label-length wire encoding，根名为单个 `0x00`。

| 规范面 | 业务场景 | 现状 | 缺口 |
|---|---|---|---|
| 连接模型 | client/server UDP 单 datagram | 已实现 | 多会话调度 G-DHCPV6-3 |
| 消息与响应 | 1–13 与场景序列 | 1–13 分支已实现 | 场景逐项 cases 不全 |
| 状态机 | 发现、租约、释放、relay | planner/scenario 编排 | 重传定时器未建模 |
| 字段编码 | TLV、BE、IPv6、DUID | builder 已实现 | 截断/未知 option cases 缺失 |
| 错误处理 | 非 IPv6、非法 type、超限 | Validate 返回错误 | 负例 cases 缺失 |
| 超时与活性 | UDP 无连接保活 | 由任务边界终止 | 定时重传未建模 |
| NAT/代理 | relay 地址与 option 9 | relay config 已实现 | 多 relay 组合缺 case |
| 版本方言 | RFC 8415 消息/option | RFC 8415 基线 | 厂商 option 未定义 |

### 3.1 命令/响应矩阵

消息顺序与响应关联的可观察约束：SOLICIT(1)→ADVERTISE(2) 或启用 Rapid Commit 时直接 REPLY(7)；REQUEST(3)/RENEW(5)/REBIND(6)/RELEASE(8)/DECLINE(9)/CONFIRM(4) 各由 REPLY(7) 响应；INFORMATION-REQUEST(11) 由 REPLY(7) 响应；RECONFIGURE(10) 触发 RENEW(5) 或 INFORMATION-REQUEST(11) 后再由 REPLY(7) 响应；RELAY-FORW(12)/RELAY-REPL(13) 通过 option 9 关联内层消息。所有同一事务的普通消息共享同一个 3B transaction-id；relay 外层不携带 transaction-id，关联必须沿 option 9 的内层消息检查。生成器按 `messages[]` 或场景函数的顺序逐 datagram 发送，不自动重传或重排。

| 请求/事件 | 正常响应 | 终止或失败 |
|---|---|---|
| SOLICIT | ADVERTISE 或 Rapid REPLY | 缺地址/非法 option → planner error |
| REQUEST | REPLY | 非法消息字段 → planner error |
| RENEW/REBIND | REPLY | 缺租约地址 → planner error |
| RELEASE/DECLINE/CONFIRM | REPLY | 字段校验失败 → planner error |
| INFORMATION-REQUEST | REPLY | option 超限 → planner error |
| RECONFIGURE | RENEW→REPLY | scenario 冲突 → planner error |
| RELAY-FORW | RELAY-REPL | relay 字段/hop 非法 → planner error |

### 3.2 数据形态变体

| 形态 | 编码/边界 | 当前实现 | 用例状态 |
|---|---|---|---|
| DUID-LLT/EN/LL | 类型化变长，序列化 ≤128B | builder/Validate | G-DHCPV6-3 |
| IA_NA/IA_TA/IAADDR | IAID、租约地址、T1/T2 | builder | SARR 基础覆盖 |
| IAPD/IAPREFIX | 前缀与前缀长度 | builder | G-DHCPV6-3 |
| ORO/StatusCode/DNS name | option TLV，DNS wire name | builder | G-DHCPV6-3 |
| Relay option 9 | 内层消息包装 | relay builder | G-DHCPV6-3 |
| 空/未知/截断 option | 长度与 MTU 边界 | Validate/解析边界 | G-DHCPV6-3 |

### 3.3 商业行为到用例映射

| 行为 | 规范/现网依据 | 用例 | 当前结论 |
|---|---|---|---|
| 四步地址分配 | RFC 8415 §18；现网 DHCPv6 SARR 抓包 | `dhcpv6_smoke_01` | 已映射 |
| Rapid Commit | RFC 8415 §18.1；商业客户端配置项 | G-DHCPV6-3 | 待抓包确认，确认方式：采集客户端一次交互 |
| Relay 包装 | RFC 8415 §19；商业 relay 转发 | G-DHCPV6-3 | 待抓包确认，确认方式：采集 relay-forward/reply |

### 3.4 三路对照

| 面 | 依据 | 设计取舍 |
|---|---|---|
| 规范原文 | RFC 8415 §§6–7、11、15–21 | TLV/BE/XID/relay 作为硬约束 |
| 商业行为 | ISC Kea 2.x DHCPv6 文档与 SARR/relay 抓包 | 采用逐 datagram、XID 关联；真实重试待抓包 |
| 开源实现 | Kea 2.x `src/bin/dhcp6` 消息/option builder 思路 | 采用类型化 option builder，不复制代码；厂商扩展另立 cases |

### 3.5 候选方案

| 方案 | 优点 | 代价 | 选择 |
|---|---|---|---|
| 场景函数直接生成固定消息序列 | 顺序确定、验证简单、包数线性 | 复杂事务扩展需加分支 | 采用，符合当前 `scenario.go` |
| 通用状态机按事件驱动 | 可表达重传、异步 relay、多会话 | 状态、调度和测试成本高 | 暂不采用；需求出现多会话时迁移 |
| option 统一 TLV builder | 编码路径一致、边界集中校验 | builder 参数较多 | 采用 |
| 每场景手写 option 字节 | 初期短 | 易重复、难审计长度 | 不采用 |

## 4. 依赖与错误处理

| 依赖层/输入 | 失败返回 | 继续或中断 | 重试/超时 |
|---|---|---|---|
| IPv6 地址 | `source/destination IP must be IPv6` | 中断当前规划 | 不重试 |
| UDP 端口/方向 | `invalid direction` 或默认 546/547 | 中断 | 不重试 |
| messages/scenario | `at least one message`、冲突或 `unknown scenario` | 中断 | 不重试 |
| relay 字段 | `relay message requires relay_fields`、`relay_ip is required` | 中断 | 不重试 |
| option/DUID | `exceeds MTU limit`、`DUID too long` 等 | 中断 | 不重试 |
| MAC 自动 DUID | `src_mac is required` | 中断 | 不重试 |

错误由 `Planner.Validate` 返回给上层任务；不产生部分成功包。

## 5. 性能与验收

单消息包数为 1，场景包数等于编排消息数，生成时间和内存随消息数线性；option 总长上限 1452 字节，DUID 128 字节，relay hop 32；队列/并发由通用 pipeline 限制，DHCPv6 层不聚合消息。CPU 主要消耗 TLV 序列化、IPv6/UDP 校验和与 Ethernet 封装。

pcap 验收读取 `cases/dhcpv6.json` 的 packet_count、msgtype、XID、IPv6、UDP、MAC 字段；网卡验收用同一断言在 tcpdump 捕获中检查每个 datagram。当前未宣称两路已复跑。

## 6. 八要素落地

| 要素 | 设计 |
|---|---|
| 文件 | `internal/protocol/dhcpv6/{planner,scenario,options,layer_gen}.go` |
| 接口 | layer registry → translate → Planner.Validate/Plan/Generate |
| 结构 | IPv6→UDP→DHCPv6，终结层持有 messages/scenario/options |
| 流程 | 转换、校验、场景展开、TLV 编码、封装 |
| 错误 | Validate 锚词返回，错误即中断且不输出半流 |
| 性能边界 | 1452 option、128 DUID、32 hop、单 datagram |
| 冲突点 | 端口默认值与 flow 默认源端口；relay 端口固定 547 |
| 回滚 | 仅回滚本协议层链/文档；不改通用 registry；旧 case 迁移失败则阻断发布 |

## 7. 动态字段清单

| 字段 | 策略 | 理由/序号位置 |
|---|---|---|
| `ip.src`/`ip.dst` | fixed/inc/rand 按通用层策略 | 第 i 流由 tuple generator 取值 |
| `udp.src_port`/`udp.dst_port` | fixed/inc/rand；0 按方向解析 546/547 | `planner.go:443-448` |
| `eth.src_mac`/`eth.dst_mac` | fixed/inc/rand 按通用层策略 | 第 i 流由 tuple generator 取值 |
| `dhcpv6.xid` | 静态结构中由 planner 生成 | `planner.go:398`，消息序号 i |
| DUID、IAID、租约、options | 不开放动态 | 业务 allowlist 无 dhcpv6 项；需补代码后立项 |

## 8. 门1 §1–§14 对照

| 门1条目 | 对照结论 | 证据 |
|---|---|---|
| §1 | 目标形状为 layers 唯一真相；地址/MAC/端口/业务均在对应层，旧顶层键已迁出；当前 Fields/translate 接线缺失，未宣称可执行 | §1、cases/dhcpv6.json、G-DHCPV6-1 |
| §2 | 策略承载单协议模板，任务负责合并与总量；flow_control 承载数量 | §1、§7 |
| §3 | 会话表=单 UDP 流；事务=messages 顺序；关联=XID/option 9；插入=UDP 终结层；时间线=严格顺序 | §2–§3 |
| §4 | RFC 8415 §§6–7、11、15、18–21 提炼消息、DUID、option、relay 约束 | §2–§3 |
| §5 | 依赖链 IPv6→UDP→DHCPv6；Validate 错误中断且不输出半流 | §1、§4 |
| §6 | 单 datagram、1452 option、128B DUID、32 hop；pcap/NIC 共用断言 | §5 |
| §7 | design + testcase + cases 三件套；当前 1 正例，未落能力列为 G-DHCPV6-3 | §9 |
| §8 | 先文档、后实现/回归；本文件只描述 as-built 与待实现边界 | §9 |
| §9 | RFC/实现/cases 三源对照；商业/开源抓包未取到的部分明确待确认 | §3.3–§3.4 |
| §10 | 自审与缺口闭环；不得用删除断言消除缺口 | §9 |
| §11 | DHCPv6 是 IPv6 上的地址配置消息，XID 关联请求/响应，relay 用 option 9 | §2–§3 |
| §12 | 四元组 fixed/inc/rand 与序号见 §7；DHCPv6 业务对象动态关闭 | §7、G-DHCPV6-2 |
| §13 | registry 终结层依赖 UDP；不新增 schema | §1 |
| §14 | pcap/NIC 使用同一 JSON expect；当前未宣称两路已复跑 | §5、testcase §6 |

## 8.1 三强制展开

- **§1 旧键去向**：`src_ip/dst_ip`→`ip.src/dst`；`src_mac/dst_mac`→`eth.src_mac/dst_mac`；端口→`udp.src_port/dst_port`；业务→`dhcpv6`；数量→任务级 `flow_control`。完整目标形状见 §1 JSON。
- **§3 五件套**：会话表、事务序列、XID/option 9 关联、UDP 终结层插入位置、严格消息时间线见 §2–§3；无连接协议不适用 FIN/RST/保活。
- **§12 动态清单**：`ip.src/dst`、`udp.src_port/dst_port`、`eth.src_mac/dst_mac` 走通用策略；XID 为 planner 运行期生成并跨同事务消息复用；DUID/IAID/租约/options 不开放动态，见 §7。

## 9. D/T/C 对账、缺口与未运行边界

| 面 | 当前事实 | 证据/边界 |
|---|---|---|
| D（design） | 1 个严格层链正例契约，覆盖 SARR、XID、IPv6/UDP/MAC 和 IAADDR 可观察面 | 本文件 §1–§8.1 |
| T（testcase） | 1 个正例、0 个负例、0 个迁移例；负例和扩展场景只登记为计划 | `docs/protocols/dhcpv6/testcase.md` §2、§4 |
| C（cases） | JSON 解析得到 1 条，ID 唯一；层序 `eth/ip/udp/dhcpv6`；`packet_count=4`；字段断言 18 条，其中 3 条 `same_as_packet` | `trafficgen/test/protocol_pcap/cases/dhcpv6.json`；本轮实际解析 |

代码事实阻塞必须与“已覆盖”分开：`validateScenario` 当前只校验场景名及禁止同时设置 `messages`，未校验需要租约地址的场景是否提供 `default_leased_addr`；缺省值会进入地址序列化而非返回设计 §4 所述错误。`scenario=relay` 未提供 `relay_config` 时，`buildScenarioMessages` 会解引用空配置，故该输入不能宣称为已验证负例；即使配置存在，relay 内层序列化失败仍有回退输出裸内层消息的实现分支，需代码修复后再落 relay 正例。上述均为 G-DHCPV6-5，未修改代码、未计入覆盖。

- G-DHCPV6-2：业务动态契约尚未开放；迁入计划是增加终结层 allowlist、动态字段解析和按流序号测试。
- G-DHCPV6-3：当前 cases 只有 SARR；迁入计划是按场景、option 边界、relay 和错误锚词逐例增加。
- G-DHCPV6-4：历史结果文件不是本轮验收证据；P5 用同一 JSON 分别完成 pcap/NIC 验收。
- G-DHCPV6-5：租约前置校验和 relay 缺配置/回退分支未闭环；修复并补失败/成功例后才能移出代码阻塞清单。

本轮未运行 suite、server、MCP、pcap 或 NIC；没有测试通过数字，也没有把代码单测结果当作协议 PCAP 验收证据。

v1.2（2026-10-01）：按当前实现补齐 D/T/C 实际统计、动态/边界与代码阻塞；明确未运行边界。自审 2 轮，末轮干净。
