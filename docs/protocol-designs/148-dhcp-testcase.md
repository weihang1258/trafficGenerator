# DHCPv4 测试用例契约（as-built）

## 1. 范围与原子性

cases JSON 是机器权威。当前只有一个集成冒烟用例；它验证完整 DORA，不代表未登记的单字段、边界或负例已经覆盖。每条断言均应以 RFC 2131、设计 §3–§5 或实际 tshark 字段为依据。负例必须只有 `expect_error` 与 `error_contains`。

## 2. 逐 ID 索引

| ID | 场景 | 依据链 | 包数 | 断言 |
|---|---|---|---:|---|
| `dhcp_smoke_01` | DHCP DORA：Discover/Offer/Request/ACK；`[udp,dhcp]`；flow 默认源端口 12345，端口解析保留该显式值 | RFC 2131 §3.1、§4.1；设计 §3–§5；`planner.go:649-784` | 4 | p1 UDP dst 67；p1 type/op=1，option53=1，flags=0；p2 type/op=2，option53=2，yiaddr=192.168.1.100，option54=192.168.1.1；p3 option53=3，option50=192.168.1.100；p4 type/op=2，option53=5，yiaddr=192.168.1.100；四包 chaddr=02:00:00:00:00:01；p2/p3/p4 xid same_as p1 |

机器来源：`trafficgen/test/protocol_pcap/cases/dhcp.json:2-140`。该 JSON 的 `expect.packet_count=4`，共 21 个 field 条目（含 3 个 xid 关联条目）；文档不增加或删改其断言。

## 3. 五层覆盖矩阵

| 层 | 已有原子点 | 缺口/边界 |
|---|---|---|
| 功能 | DORA 四状态、option53、xid 关联 | NAK、RELEASE、INFORM、RENEW、REBIND；manual 8 message types；relay |
| 性能 | 四个 UDP datagram、单 payload | options 1232、相邻 1233、255 长度字段、最大固定头字段；多 flow |
| 数据 | yiaddr、server-id、requested-ip、flags、MAC | option 1/3/6/12/15/50/51/54/55/58/59/60/61/82/119，各值域/空/最大；保留 option 52/255 |
| 地址与流 | UDP dst port 67、DHCP MAC、广播型 DORA | IPv4 单流非默认端口、server/relay；IPv6 明确不适用（DHCPv4 validator 拒绝） |
| 业务 | 一个 DORA 租约事务及共享 xid | 多会话独立 xid/四元组、重试/重连/异常取消；DHCP layer 无并发/保活/FIN/RST |

## 4. 存量用例审计

| ID | 去向 | 原因 |
|---|---|---|
| `dhcp_smoke_01` | 保留 | 唯一现有 executable case，断言 DORA 端到端可观察字段 |

没有其他 DHCP ID 可审计；未来 scenario 与边界不可伪装写入现有 JSON 集合。

## 5. 缺口登记（与设计 §10 同号同义）

| ID | 现象 | 证据 | 归属阶段 |
|---|---|---|---|
| G-DHCP-1 | 六种 scenario 中仅 dora 有 case；manual 8 message types 无逐 type 正例 | `cases/dhcp.json` 仅 1 ID；`scenario.go:200-296` | 用例覆盖 |
| G-DHCP-2 | 动态字段策略/多流序号未实现及未测 | `layer_gen.go:83-85,117-217` | 生成器/用例覆盖 |
| G-DHCP-3 | IPv6/relay/server/非默认端口无 case（IPv6 由 validator 拒绝，属合法不适用生成面） | `planner.go:100-115,649-747` | 用例覆盖 |
| G-DHCP-4 | validator/planner 负分支与 option 边界、截断、超 MTU 无 `expect_error` case | `planner.go:100-387`（锚词清单见设计 §8），JSON 无 `expect_error` | 用例覆盖 |
| G-DHCP-5 | tracked 结果产物过期：末次提交 `a674fe96`（2026-09-05）早于 `0417be5`（2026-09-13），pcap 留档目录不存在 | `git log -1 -- trafficgen/docs/protocol-pcap-test/dhcp.md`；`dhcp/` 目录缺失 | 产物阶段（P5 重跑后重生成） |
| G-DHCP-6 | executable case 仍把 `dhcp` 放在 `layers` 外，不能证明严格层链唯一真相 | `cases/dhcp.json:6-19`；目标形见设计 §1 | 配置迁移阶段（迁移后重跑） |
| G-DHCP-7 | scenario validator 只预检合成消息首条，后续消息 options 超限要到 builder 才可能失败 | `planner.go:349-371,819-823`；设计 §8 | validator/用例阶段（逐消息预检并补负例） |

## 6. 覆盖反查门建议断言

以下行供 `coverage_gate.py` 登记，当前均不得申报已过（除标明已有项）。其中 scenario options 的上限检查只覆盖合成消息首条；后续消息逐条预检仍是 G-DHCP-7，不能把 builder 期失败写成 validator 已通过。

1. `dhcp_smoke_01` 存在且 `packet_count==4`（已具备）。
2. layers 精确为 `[udp,dhcp]`（目标形已具备；executable case 仍有层链外顶层 `dhcp`，缺口 G-DHCP-6）。
3. packet 1..4 option53 为 `1,2,3,5`（已具备）。
4. packet 2/3/4 xid 与 packet 1 相等（已具备）。
5. p1 UDP dst 67 与 MAC 四包一致（已具备；显式 src port 12345 口径写入 notes）。
6. 六种其它 scenario 各自 packet sequence/option presence（缺口 G-DHCP-1）。
7. manual mode 每个 message type 1..8 可观察 op/option53（缺口 G-DHCP-1）。
8. IPv4-only validator 拒绝 IPv6 且任务返回失败（缺口 G-DHCP-3）。
9. invalid role/type/direction、HType/HLen、MAC/IP、保留 options 的 error_contains（缺口 G-DHCP-4）。
10. 255/256 字节字段与 options 1232/1233 边界（缺口 G-DHCP-4）。
11. default/inc/rand/list/pattern 动态值与回绕/可复现（缺口 G-DHCP-2）。
12. pcap 与 NIC 输出对同一 `[udp,dhcp]` 契约（NIC 待主线程执行）。

## 7. 产物过期核验

`trafficgen/docs/protocol-pcap-test/dhcp.md` 已被 git 跟踪，末次提交 `a674fe96`（2026-09-05）**早于** `0417be5`（2026-09-13 扁平判死基线），且其链接的 `dhcp/` pcap 留档目录不存在；按 pcep G-PCEP-11 同口径登记为过期产物（缺口 G-DHCP-5，与设计 §10/§14 一致），不把它当作当前 cases 契约，也不得据此声称套件已复跑。

## 8. 复核记录

自审 3 轮，末轮干净：脚本机读 cases ID、`packet_count=4`、21 条 field 条目（含 3 条 same_as_packet xid 关联）逐条对照本稿 §2；五层覆盖、缺口三要素、建议断言行与设计 §9 一致性复核；当前 JSON 只有 1 个 ID，未虚报缺口为已通过。
