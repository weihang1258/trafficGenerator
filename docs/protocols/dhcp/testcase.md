# DHCPv4 测试用例契约（as-built）

## 1. 范围与原子性

cases JSON 是机器权威。当前只有一个集成冒烟用例；它验证完整 DORA，不代表未登记的单字段、边界或负例已经覆盖。每条断言均应以 RFC 2131、设计 §3–§5 或实际 tshark 字段为依据。负例必须只有 `expect_error` 与 `error_contains`。

## 2. 逐 ID 索引

| ID | 场景 | 依据链 | 包数 | 断言 |
|---|---|---|---:|---|
| `dhcp_smoke_01` | DHCP DORA：Discover/Offer/Request/ACK；`[udp,dhcp]`；flow 默认源端口 12345，端口解析保留该显式值 | RFC 2131 §3.1、§4.1；设计 §3–§5；`planner.go:390-649` | 4 | p1 UDP dst 67；p1 type/op=1，option53=1，flags=0；p2 type/op=2，option53=2，yiaddr=192.168.1.100，option54=192.168.1.1；p3 option53=3，option50=192.168.1.100；p4 type/op=2，option53=5，yiaddr=192.168.1.100；四包 chaddr=02:00:00:00:00:01；p2/p3/p4 xid same_as p1 |

机器来源：`trafficgen/test/protocol_pcap/cases/dhcp.json:2-140`。该 JSON 的 `expect.packet_count=4`，共 21 个 field 条目（含 3 个 xid 关联条目）；文档不增加或删改其断言。

## 3. 五层覆盖矩阵

| 层 | 已有原子点 | 缺口/边界 |
|---|---|---|
| 功能 | DORA 四状态、option53、xid 关联 | NAK、RELEASE、INFORM、RENEW、REBIND；manual 8 message types；relay |
| 性能 | 四个 UDP datagram、单 payload | options 1232、相邻 1233、255 长度字段、最大固定头字段；多 flow |
| 数据 | yiaddr、server-id、requested-ip、flags、MAC | option 1/3/6/12/15/50/51/54/55/58/59/60/61/82/119，各值域/空/最大；未支持 option 52/255 |
| 地址与流 | UDP dst port 67、DHCP MAC、广播型 DORA | IPv4 单流非默认端口、server/relay；IPv6 由 DHCPv4 validator 拒绝，负向确认列入 G-DHCP-3 |
| 业务 | 一个 DORA 租约事务及共享 xid | 多会话独立 xid/四元组、重试/重连/异常取消；DHCP layer 无并发/保活/FIN/RST |

## 4. 存量用例审计

| ID | 去向 | 原因 |
|---|---|---|
| `dhcp_smoke_01` | 纳入 | 唯一现有 executable case，断言 DORA 端到端可观察字段 |

没有其他 DHCP ID 可审计；未来 scenario 与边界不可伪装写入现有 JSON 集合。

## 5. 测试点清单先行与三源回指

清单按 RFC 2131 §3.1、§4.1、§4.3、§4.4 反推，再与设计 §3–§8 和现网 DORA pcap 对账：

| 规范条文 | 业务场景 | 代码分支 | 用例/缺口 |
|---|---|---|---|
| §4.4.1 Discover/Offer | 初始租约 | `buildScenarioMessages`, option 53 | `dhcp_smoke_01` |
| §4.4.1 Request/ACK | 选择并确认租约 | scenario DORA、xid 关联 | `dhcp_smoke_01` |
| §4.4.1 NAK/Release/Inform | 拒绝、释放、配置通知 | scenario 分支 | G-DHCP-1 |
| §4.4.5 Renew/Rebind | 单播续租、广播重绑定 | renew/rebind 分支 | G-DHCP-1、现网 pcap 待确认 |
| §4.1 固定头/options | 边界与非法字段 | validator/encoder | G-DHCP-4 |
| §4.1 广播/relay | 广播与中继 | resolve IP/MAC、giaddr | G-DHCP-3 |
| §4.1 IPv4 | 地址族约束 | IPv4 validator | G-DHCP-3 |

三源结论：规范以 RFC 2131 上述章节为准；设计对应 §3–§8；现网已确认行为仅 `dhcp_smoke_01` 的四包 DORA/XID/MAC 字段。商业 DHCP 广播与续租行为尚无本地 pcap，确认方式为抓取 dnsmasq 或 ISC DHCP 的 DORA/renew/rebind 流量后逐字段对账，不把待确认项计入覆盖。

## 6. 颗粒度、强度与失败路径

现有例是数据+业务+现网复合冒烟，断言到包序、option 值、地址和 XID 关联；不能再拆的单点清单见上表。枚举逐值、固定头长度/选项边界、动态策略整格和正交组合（角色×方向×地址族×单/多流）均因代码或 cases 不足登记为 G-DHCP-2/3/4。负例必须经 MCP 提交坏配置，断言 `expect_error` 与准确 `error_contains`，当前尚未登记任何负例，因此不存在伪成功断言。

§3.15 三项：同一流多轮消息=DHCP 消息数组已有序列，但无独立 case（G-DHCP-1）；非正常结束=UDP 无 FIN/RST，协议层不产生该动作，仍需补 validator/取消负例确认（G-DHCP-4）；长保活=无自动保活/定时器，需以 renew/rebind case 或立项（G-DHCP-1）。DHCP 无长连接与派生数据流，`sessions[]` 不属于当前配置形状；多会话/并发覆盖仍由 G-DHCP-3 登记。

## 7. 覆盖强度与存量去向

唯一存量 ID `dhcp_smoke_01` 合入本版，未发现其他 DHCP ID。规范逻辑点总数与覆盖数不能以当前 1 例宣称全覆盖：已覆盖 1 个 DORA 事务点；NAK、RELEASE、INFORM、RENEW、REBIND、固定头/option 边界、非法配置、relay 和动态策略均为缺口。复杂现网场景（多会话/多事务/异常/NAT 至少三类交织）当前无引擎表达与证据，登记 G-DHCP-3。

## 8. D/T/C 三方对账

| 维度 | testcase | design | cases JSON |
|---|---|---|---|
| ID/顺序 | `dhcp_smoke_01` | §18 对账为同一 ID | 1 例，同 ID |
| 配置形状 | `[udp,dhcp]`，业务配置住 DHCP 层 | §1/§18 明确严格层链 | `spec_json` 顶层仅 `layers` |
| 包数 | 4 | DORA 4 包 | `packet_count=4` |
| 断言 | 21 field 条目，含 3 条 XID 关联 | §3–§5 语义范围 | JSON 21 条 field，same_as 2/3/4 |

当前 `cases` 只有 1 个正例；未实现或未覆盖的场景不增 ID、不伪造负例。空配置默认 DISCOVER 仍是实现能力边界（当前 JSON 已声明 DORA），不将其冒充为独立覆盖；其他 scenario 已在 generator 中但无 case，归入 G-DHCP-1。

## 9. 缺口登记（与设计 §13 同号同义）

| ID | 现象 | 证据 | 归属阶段 |
|---|---|---|---|
| G-DHCP-1 | 六种 scenario 中仅 dora 有 case；manual 8 message types 无逐 type 正例 | `cases/dhcp.json` 仅 1 ID；`scenario.go:200-296` | 用例覆盖 |
| G-DHCP-2 | 动态字段策略/多流序号未实现及未测 | `layer_gen.go:83-85,117-217` | 生成器/用例覆盖 |
| G-DHCP-3 | IPv6/relay/server/非默认端口无 case（IPv6 由 validator 拒绝，生成面需负向确认） | `planner.go:100-123,391-591` | 用例覆盖 |
| G-DHCP-4 | validator/planner 负分支与 option 边界、截断、超 MTU 无 `expect_error` case | `planner.go:100-387`（锚词清单见设计 §11），JSON 无 `expect_error` | 用例覆盖 |
| G-DHCP-5 | tracked 结果产物过期：末次提交 `a674fe96`（2026-09-05）早于 `0417be5`（2026-09-13），pcap 留档目录不存在 | `git log -1 -- trafficgen/docs/protocol-pcap-test/dhcp.md`；`dhcp/` 目录缺失 | 产物阶段（P5 重跑后重生成） |

## 10. 覆盖反查门建议断言

以下行供 `coverage_gate.py` 登记，当前均不得申报已过（除标明已有项）：

1. `dhcp_smoke_01` 存在且 `packet_count==4`（已具备）。
2. layers 精确为 `[udp,dhcp]`（已具备 notes）。
3. packet 1..4 option53 为 `1,2,3,5`（已具备）。
4. packet 2/3/4 xid 与 packet 1 相等（已具备）。
5. p1 UDP dst 67 与 MAC 四包一致（已具备；显式 src port 12345 口径写入 notes）。
6. 六种其它 scenario 各自 packet sequence/option presence（缺口 G-DHCP-1）。
7. manual mode 每个 message type 1..8 可观察 op/option53（缺口 G-DHCP-1）。
8. IPv4-only validator 拒绝 IPv6 且任务返回失败（缺口 G-DHCP-3）。
9. invalid role/type/direction、HType/HLen、MAC/IP、未支持 options 的 error_contains（缺口 G-DHCP-4）。
10. 255/256 字节字段与 options 1232/1233 边界（缺口 G-DHCP-4）。
11. default/inc/rand/list/pattern 动态值与回绕/可复现（缺口 G-DHCP-2）。
12. pcap 与 NIC 输出对同一 `[udp,dhcp]` 契约（NIC 待主线程执行）。

## 11. 产物过期核验

`trafficgen/docs/protocol-pcap-test/dhcp.md` 已被 git 跟踪，末次提交 `a674fe96`（2026-09-05）**早于** `0417be5`（2026-09-13 扁平判死基线），且其链接的 `dhcp/` pcap 留档目录不存在；按 pcep G-PCEP-11 同口径登记为过期产物（缺口 G-DHCP-5，与设计 §13/§14 一致），不把它当作当前 cases 契约，也不得据此声称套件已复跑。

## 12. 复核记录

自审 3 轮，末轮干净：脚本机读 cases ID、`packet_count=4`、21 条 field 条目（含 3 条 same_as_packet xid 关联）逐条对照本稿 §2；五层覆盖、缺口三要素、建议断言行与设计 §12 一致性复核；当前 JSON 只有 1 个 ID，未虚报缺口为已通过。
