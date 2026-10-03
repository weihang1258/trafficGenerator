# DHCPv6（RFC 8415）测试用例契约

> 版本 v1.1（2026-09-30）。机器契约 `trafficgen/test/protocol_pcap/cases/dhcpv6.json` 是唯一例数、ID、包数和断言来源；本车道不运行 suite。

## 1. 形状与测试点先行

目标层链为 `eth → ip → udp → dhcpv6`；正例 `spec_json` 顶层仅 `layers`。registry 虽注册 DHCPv6 终结层并依赖 `udp`，但当前缺少该层 `Fields` 且 translate 缺少 `case "dhcpv6"`，因此本层链形状尚不能宣称已可执行；四元组字段由承载层配置，消息与 option 字段由 DHCPv6 终结层配置。

| 规范条文 | 业务场景 | 代码分支 | 缺口/测试点 |
|---|---|---|---|
| RFC 8415 §6.4/§7 | SARR 地址发现 | `scenario.go:210-220` | 已覆盖 T-DHCPV6-01 |
| RFC 8415 §15.1 | 同一交换共享 XID | `planner.go:398` | 已覆盖 T-DHCPV6-01 |
| RFC 8415 §11 | DUID-LLT/EN/LL | `options.go`/planner Validate | G-DHCPV6-3，需逐 DUID 类型 |
| RFC 8415 §21 | TLV、IA_NA、ORO、StatusCode、DNS | `options.go:31-126` | G-DHCPV6-3，需逐 option/边界 |
| RFC 8415 §19 | Relay-forward/reply 与 option 9 | `scenario.go:408-468` | G-DHCPV6-3，需 relay 正例 |
| RFC 8415 §18.1 | Rapid Commit | `scenario.go:222-235` | G-DHCPV6-3，需正例 |
| 实现校验 | IPv4、空消息、非法 type、hop/MTU/DUID/MAC | `planner.go:141-291` | G-DHCPV6-3，需真实失败例 |

## 1.1 行为面清单与覆盖结论

覆盖审查按 RFC 8415 §7、§11、§15、§18–§21 逐项枚举，而不是按现有例反推。消息类型行为面为：SOLICIT/ADVERTISE/REQUEST/CONFIRM/RENEW/REBIND/REPLY/RELEASE/DECLINE/RECONFIGURE/INFORMATION-REQUEST 及 RELAY-FORW/RELAY-REPL；数据面为 24-bit XID、DUID-LLT/EN/LL、IA_NA/IA_TA/IAADDR/IAPD/IAPREFIX、ORO、PREFERENCE、ELAPSED_TIME、RELAY_MSG、STATUS_CODE、RAPID_COMMIT、RDNSS、DNSSL、SNTP、INFO_REFRESH_TIME 的字段值域、长度、端序、空值和超限；交互面为 SARR、Rapid Commit、续租/重绑定、释放/冲突声明/确认、无状态请求、重配置和 relay 包装；承载面为 IPv6/UDP 默认 546/547、显式非默认端口、单流与多 flow。当前仅 `dhcpv6_smoke_01` 证明 SARR 的一个复合路径；其余消息类型、option 逐项边界、relay、非默认端口、多 flow 和所有 validator 错误均是 G-DHCPV6-3 待实现/待落例，不计入已覆盖统计。由于 DHCPv6 是无连接 UDP，FIN/RST 和连接保活不适用；重传定时器未建模，不能把同一 XID 的静态重复包冒充重传覆盖。


## 2. 用例索引与三源回指

当前 JSON **1 例 = 1 正例、0 负例、0 迁移例**：

| ID | 类型/场景 | 规范→实现→现网 | 包数与不可再分断言 |
|---|---|---|---|
| `dhcpv6_smoke_01` | 正；SARR | RFC 8415 §6.4/§7 → `scenario.go:210-220` → DHCPv6 SARR 抓包行为 | 4；msgtype 1/2/3/7，dst port 547，IPv6 双向地址，租约地址，hlim 64，MAC，XID 存在且包 2–4 `same_as_packet:1` |

现网映射以已记录的 SARR 抓包面为依据；Rapid Commit、relay 及厂商差异尚无本车道抓包，确认方式分别是采集对应商业/开源客户端一次交互后补 ID，不把待确认写成已覆盖。

## 3. 正例断言边界

`dhcpv6_smoke_01` 的 `packet_count=4`，每包一个 UDP datagram。packet 1/3 为上行（源端口 12345、目标 547），packet 2/4 方向反向；JSON 钉 packet 1/2/3/4 的 msgtype 和租约地址、packet 1/3 的 IPv6 dst、packet 1 的 IPv6 src/MAC/hlim/目标端口。XID 是运行期三字节值：packet 1 只断言存在，packet 2–4 逐一与 packet 1 相同。单播目标是生成器选择，RFC 允许的 ff02::1:2 多播未宣称覆盖。

## 4. 失败路径契约

当前 JSON 没有 `expect_error`，因此没有可声称“真会红”的负例。下列是 G-DHCPV6-3 的原子测试计划；落地时每例只带 `expect_error` 与和代码逐字一致的 `error_contains`，不混入成功断言：

| ID/输入 | 锚词（实现字面） | 证据 |
|---|---|---|
| `dhcpv6_neg_ipv4_src` / IPv4 源地址 | `source IP must be IPv6` | `planner.go:149` |
| `dhcpv6_neg_ipv4_dst` / IPv4 目的地址 | `destination IP must be IPv6` | `planner.go:158` |
| `dhcpv6_neg_empty_messages` / 空 manual | `at least one message is required` | `planner.go:183` |
| `dhcpv6_neg_msgtype_range` / type 0 | `invalid msg-type` | `planner.go:190` |
| `dhcpv6_neg_relay_no_fields` / relay 无字段 | `relay message requires relay_fields` | `planner.go:197` |
| `dhcpv6_neg_hop_overflow` / hop 33 | `exceeds limit` | `planner.go:200` |
| `dhcpv6_neg_direction` / sideways | `invalid direction` | `planner.go:218` |
| `dhcpv6_neg_options_mtu` / options >1452 | `exceeds MTU limit` | `planner.go:230` |
| `dhcpv6_neg_missing_mac` / 自动 DUID 无 MAC | `src_mac is required` | `planner.go:253` |
| `dhcpv6_neg_unknown_scenario` / foo | `unknown scenario` | `scenario.go:90` |

## 4.1 负例覆盖审查状态

设计已列出 validator 错误分支，但当前机器 JSON 没有负例，因此不能声称这些错误已经经真实任务链验证。待实现阶段应为每个错误锚词建立单故障 `expect_error` 用例，并确认任务终态失败且不产生成功 pcap：IPv4 源/目的、空 manual、msg-type 越界、relay 缺字段、hop-count 33、非法 direction、options 超 MTU、缺 MAC、未知 scenario，以及设计 §4 中列出的 DUID/relay 地址错误。负例的 `expect` 必须严格只有 `expect_error` 与 `error_contains`。

当前实现边界需要单列而不能伪装成负例：`scenario` 模式对需要租约的场景没有 `default_leased_addr` 前置错误，空地址会继续进入 builder；`scenario=relay` 缺少 `relay_config` 时存在空指针风险，且 relay 内层构造失败有回退裸消息分支。这两类均是代码阻塞（G-DHCPV6-5），当前没有对应 case，也没有运行验证；先修代码，再分别补真负例和 relay 正例。
## 5. §3.15、动态与存量审计

- 同连接多轮操作：SARR 四包共享 XID，已由 `dhcpv6_smoke_01` 覆盖。
- 非正常结束：UDP 无 FIN/RST；以 Validate 错误负例立项覆盖，当前尚未落 JSON。
- 长保活：DHCPv6 没有连接保活语义，已判定该测试维度无协议动作，不伪造用例。
- 动态整格：`ip.src/dst`、`udp.src_port/dst_port`、`eth` MAC 可用通用 fixed/inc/rand；DHCPv6 业务对象动态未开放，见设计 G-DHCPV6-2。XID 按消息序号生成/关联而不固化值。
- 存量 `dhcpv6_smoke_01`：合入并已迁移 `src_ip/dst_ip/src_mac/dhcpv6` 到对应层；无作废例、无等价覆盖例。

## 6. 对账与修订

JSON 实际 ID 集合 `{dhcpv6_smoke_01}`，正例 1、负例 0、迁移例 0；本文索引完全一致。三件套现状：design/testcase/cases 的 ID、场景、packet_count=4 和 18 条字段断言一致；负例与待实现场景不进入当前 JSON。历史结果文件不作为本轮证据；pcap 与 NIC 未来必须使用同一 JSON 断言。

**覆盖反查门建议断言**：① JSON 长度=1且 ID 顺序固定；② spec_json 顶层键仅 `layers`，层序为 eth/ip/udp/dhcpv6；③ packet_count=4；④ msgtype 集合按包序为 1/2/3/7；⑤ XID 一条存在断言+三条 `same_as_packet:1`；⑥ 非负例顶层键为0；⑦ 无 `expect_error` 例时不得声称负路径已覆盖；⑧ `udp.dstport=547`、hlim=64、租约地址、双向 IPv6/MAC 断言保持与 JSON 一致。

G-DHCPV6-2：业务动态 allowlist 未开放，先补代码再补动态矩阵。G-DHCPV6-3：场景、option、relay 与失败路径尚未逐例落盘，按 §4 计划补齐。G-DHCPV6-4：历史结果需 P5 重跑，不引用旧 pass 数字。

v1.3（2026-10-01）：补齐实际统计（1/0/0、字段 18、same_as 3）、relay/租约代码阻塞边界和未运行边界。自审 2 轮，末轮干净。