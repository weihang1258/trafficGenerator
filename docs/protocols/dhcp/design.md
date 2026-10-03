# DHCPv4 设计契约（as-built）

## 1. 范围、规范与目标形状

实现是 DHCPv4（RFC 2131；BOOTP wire format 由 RFC 2131 §2/§4.1 定义）终结层，承载于 UDP。配置唯一真相是层链；完整当前目标形状为：

```json
{"layers":[{"udp":{}},{"dhcp":{"scenario":"dora","default_your_ip":"192.168.1.100","default_server_identifier":"192.168.1.1"}}]}
```

门1 §1 旧形逐键去向：`role`、`xid`、`scenario`、`messages`、`client_mac`、`h_type`、`h_len`、`broadcast_flag`、`secs`、`sname`、`file`、全部 `default_*` 及 message 内 `type/direction/client_ip/your_ip/server_ip/relay_agent_ip/hops/server_identifier/lease_time/t1/t2/subnet_mask/routers/dns/domain_name/hostname/domain_search/client_id/requested_ip/param_request_list/vendor_class/relay_agent_info/extra_options/broadcast` 均由 `strategy_convert.go:2586-2694` 解析进 `spec.DHCP`，目标位置是层链 `layers[].dhcp`（或同一 `DHCPConfig` 的 `messages[]`）。`src_ip/dst_ip/src_port/dst_port/src_mac/dst_mac/ttl` 不属于 DHCP 业务键，按 flow 元数据语义由 `resolvePorts/resolveIPs/resolveMACs` 和承载层消费；`count/bps/duration` 由 flow control 处理。不存在可继续放在顶层的游离 DHCP 键。

`dhcp` 缺省时生成一个 DISCOVER。`scenario` 可为 `dora|nak|release|inform|renew|rebind`，非 scenario 使用 `messages[]` 原样逐条发包。

## 2. 业务场景与五件套

现网基线是客户端获取租约（DORA）、拒绝（NAK）、释放、INFORM、续租和重绑定。一个 DHCP 会话由同一四元组和同一 xid 关联；每条消息是一个 UDP datagram，按配置顺序发出。DHCP layer 当前只生成单 flow 的消息序列；多会话/并发调度不是当前能力，需上层重复 flow 承载并分别分配 flow ID，覆盖登记为 G-DHCP-3。

| 项目 | as-built |
|---|---|
| 会话表 | 一个 flow：src/dst IP、src/dst UDP port、client MAC、xid |
| 事务序列 | DORA=Discover→Offer→Request→ACK；NAK/Release/Inform/Renew/Rebind 见 `scenario.go:200-296` |
| 关联关系 | 四个（或扩展序列）消息共享 xid；DHCP message type option 53 区分动作 |
| 插入位置 | UDP 事件流中每消息一个 event；`layer_gen.go:117-221` |
| 时间线 | `messages` 数组顺序；无自动 delay/重传/并发，ctx 取消停止 |

## 3. 线格式（可生成级）

每帧 payload = 236-byte BOOTP 固定头 + 4-byte magic cookie `0x63825363` + options + END/padding。固定头字段均 network byte order：offset 0 op(1), 1 htype(1), 2 hlen(1), 3 hops(1), 4..7 xid(uint32), 8..9 secs(uint16), 10..11 flags(uint16), 12..15 ciaddr, 16..19 yiaddr, 20..23 siaddr, 24..27 giaddr，28..43 chaddr(16)，44..107 sname(64)，108..235 file(128)。IP 字段为 4-byte IPv4；chaddr 前 hlen bytes 为 MAC，余零填充。Options 从 240 开始，逐项 `code(1)+len(1)+data`，最终 END(255)；option 53 总是第一项。

已实现 option：53 message type、50 requested IP、54 server identifier、51 lease time、58 T1、59 T2、1 subnet mask、3 routers、6 DNS、12 hostname、15 domain、119 domain search、61 client ID、55 parameter request list、60 vendor class、82 relay agent info 及 `extra_options`。所有多字节数值大端；IP 列表按 4-byte 元素。options 上限 `MaxOptionsLen=1232`（1472−236−4），超过则拒绝。

## 4. 状态机与自动派生

manual 模式不验证完整 RFC 状态机，只按消息数组生成。scenario 模式先校验角色与所需 defaults，再由 `buildScenarioMessages` 生成完整序列，并清空 defaults 后逐消息显式注入，避免错误继承：DORA 4 包；NAK 4；release 5；inform 2；renew/rebind 各 6。DISCOVER/OFFER/REQUEST/ACK 等消息 type 由 `inferOpFromType` 分为 BOOTREQUEST/BOOTREPLY，并由 `inferDirectionFromType` 推断 up/down。xid=0 时运行期随机，否则使用配置值。

## 4.1 规范矩阵与方案取舍

P1 八项矩阵（RFC 2131 §4.1、§4.3、§4.4）：

| 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|
| 连接模型：UDP 客户端/服务器 | DORA 单事务 | `planner.go:100-387` + UDP 层 | 多会话编排未实现（G-DHCP-3） |
| 消息/响应：DISCOVER/OFFER/REQUEST/ACK、NAK、DECLINE、RELEASE、INFORM | 租约获取、拒绝、释放、配置通知 | `scenario.go:200-296` | 各场景缺机器用例（G-DHCP-1） |
| 状态机：选择、绑定、续租 | DORA、renew、rebind | scenario builder 按数组生成 | 不模拟计时器/重传（G-DHCP-2） |
| 字段：BOOTP 固定头与 options | 地址、租约、路由、DNS | `encodeBootpHeader:829-910`、`encodeOptions:915+` | 全字段边界未覆盖（G-DHCP-4） |
| 错误处理：非法角色/字段/超 MTU | 配置拒绝且不产包 | `planner.go:100-387` | 负例未入 cases（G-DHCP-4） |
| 活性/超时：重试与 lease timers | 续租/重绑定 | 无自动 timer；ctx 取消 | 需确认真实超时验收方式（G-DHCP-2） |
| relay/NAT 行为 | giaddr、relay-agent-info | relay 字段可编码 | relay 现网行为无用例（G-DHCP-3） |
| 版本/方言：DHCPv4 与 IPv6 分界 | IPv4 DORA | validator 拒绝 IPv6 | DHCPv6 另协议，未迁入本层 |

### 4.2 命令×响应码矩阵

| 消息/结果 | 已实现形态 | 用例映射 | 结论 |
|---|---|---|---|
| DISCOVER→OFFER | scenario dora | `dhcp_smoke_01` | 已实现，已覆盖 |
| REQUEST→ACK | scenario dora | `dhcp_smoke_01` | 已实现，已覆盖 |
| 任意→NAK | scenario nak | G-DHCP-1 | 已实现，缺用例 |
| DECLINE/RELEASE | scenario release/manual | G-DHCP-1 | 部分实现，缺用例 |
| INFORM→ACK | scenario inform | G-DHCP-1 | 已实现，缺用例 |
| RENEW/REBIND | scenario renew/rebind | G-DHCP-1 | 已实现，缺用例 |

### 4.3 数据形态变体表

| 形态 | 代码现状 | 用例/缺口 |
|---|---|---|
| IPv4 地址、MAC、端口 | 已实现，默认值及显式值 | DORA；非默认/relay 为 G-DHCP-3 |
| 固定头 htype/hlen、hops、flags、secs | validator+encoder | 边界 G-DHCP-4 |
| 选项单值/列表/字符串/extra_options | encoder 支持 53/50/54/51/58/59/1/3/6/12/15/119/61/55/60/82 | 各值域 G-DHCP-4 |
| option overload/END/MTU 截断 | validator 拒绝未支持项/超长 | 负例 G-DHCP-4 |
| DHCPv4 IPv6 输入 | validator 拒绝 | G-DHCP-3 负向确认 |

### 4.4 商业行为→用例映射表

| 现网行为 | 依据/确认方式 | 用例 | 状态 |
|---|---|---|---|
| 客户端 DORA、共享 xid | RFC 2131 §4.4；pcap 字段 | `dhcp_smoke_01` | 已映射 |
| 广播 Discover/Offer 常见 | RFC 2131 §4.1；待抓 dnsmasq/ISC DHCP pcap | G-DHCP-3 | 待确认 |
| 续租通常单播、重绑定广播 | RFC 2131 §4.4.5；待抓 dnsmasq/ISC DHCP pcap | G-DHCP-1 | 待确认 |

### 4.5 候选方案对比

| 方案 | 来源/优点 | 代价 | 取舍 |
|---|---|---|---|
| scenario builder 自动展开 | RFC 2131 序列；配置短、顺序稳定 | 不能表达任意异常序列 | 当前采用，兼容 DORA 等常见模板 |
| messages[] 手工序列 | RFC 2131 §4.4；可表达重发/异常 | 配置长、调用方负责一致性 | 当前支持，复杂变体优先此方案 |

## 5. 地址、端口、依赖与错误处理

client 默认 68→67，server 默认 67→68，relay 默认 67→67；显式 flow 端口优先。缺省 IPv4 为 client/server/relay 的 `0.0.0.0` 到 `255.255.255.255`，缺省目标 MAC 为广播。广播消息强制目标 IP/MAC 广播；down 事件交换 IP/MAC，server 缺省源 MAC 为 `02:00:00:00:00:02`。DHCPv4 validator 拒绝 IPv6。事件携带 `SrcPort/DstPort`、`L4PortOverride=true`、TTL（默认 64）、目标 IP/MAC 覆盖，UDP 层输出一个 datagram/event。

依赖与失败处理：DHCP 依赖 UDP 层和 IPv4 地址，缺层、非法角色/type/字段、未支持 option 或超 MTU 时返回 validator 错误并中断当前流，不重试；ctx 取消或 EmitMsg 失败传播原错误；没有自动超时，调用方控制取消。完整错误锚词见 §11。

## 6. 性能设计与验收

单包 payload 上界为 1472（固定头+cookie+options）；DHCP builder 每消息一个 UDP datagram，按 messages 流式发出，不全量收集；队列和缓冲上限由上层有界队列/缓冲控制。目标吞吐、并发、CPU、内存数字尚无本协议基准，待 P5 以六类场景（基线、目标规模、压力上限、长时、并发交错、背压）实测后登记。pcap 路径逐包检查 UDP/DHCP 字段和序列；NIC 路径用 tcpdump 对同一字段集、吞吐和丢包计数复核。

## 7. 八要素实施契约

| 要素 | 结论 |
|---|---|
| 文件 | `internal/protocol/dhcp/{planner.go,scenario.go,layer_gen.go}`；本协议三份契约文件 |
| 接口 | registry validator/generator；`Plan`、`Generate`、`buildDHCPMessage` |
| 结构 | UDP 承载 + DHCP 终结层；每消息一个 event |
| 流程 | 校验 → scenario/messages 展开 → 编码固定头/options → EmitMsg |
| 错误 | validator/编码错误原样返回并终止当前流 |
| 性能边界 | 1472 payload、单 datagram/event、有界上层队列 |
| 冲突点 | 顶层 DHCP 映射与层链唯一真相冲突；已迁入 `layers[].dhcp` |
| 回滚 | 仅回滚本协议三文件；不触及代码和其他协议 |

## 8. 动态字段清单

| 字段 | fixed/inc/rand/list/pattern | 序号算法/不开理由 |
|---|---|---|
| src_ip/dst_ip | 由承载 `ip` 层统一策略 | DHCP 不重复实现；按流序号由通用层处理 |
| src_port/dst_port | 由 `udp` 层统一策略 | 端口住 UDP，DHCP 只消费事件端口 |
| xid | fixed（显式）；rand（0 缺省） | `layer_gen.go:83-85` 直接 `rand.Uint32()`；inc/list/pattern 未接线（G-DHCP-2） |
| client MAC | fixed | `DHCPConfig`/chaddr 直接编码；动态策略未接线（G-DHCP-2） |
| yiaddr/server_id/lease/t1/t2 | fixed | scenario defaults 注入；动态策略未接线（G-DHCP-2） |
| options 字符串/IP 列表 | fixed | encoder 直接编码；动态策略未接线（G-DHCP-2） |

## 9. 门1 §1–§14 对照

JSON `strategy_convert.go:2586-2694` 解析 `DHCPConfig`、`DHCPMessage` 和 extra options；registry 以 `dhcp` 取 validator/generator。validator `planner.go:100-387` 检查 IPv4、角色、消息 type、字段长度、MAC、HType/HLen、sname/file、options 上限、relay 与未支持 option。planner `Plan` 与 `DHCPGenerator.Generate` 共用 builder 语义；`buildDHCPMessage:788-825` 拼接 payload，`encodeBootpHeader:829-910` 编码固定头，`encodeOptions:915+` 编码 TLV。

## 10. 动态字段与序号（实现补充）

当前 DHCP layer 的协议关键字段为 `xid`、client MAC、地址、端口及消息字段。`xid=0` 使用 `rand.Uint32()`，不是按流序号递增；消息 packet index 从 0 起并由数组索引产生（`layer_gen.go:201`）。策略 fixed/inc/rand/list/pattern 的统一动态策略接线不在 DHCP generator 内；故 N 流动态展开、回绕、随机 seed、pattern、静态重复拒绝均为待实现边界，不将其冒充已覆盖。

## 11. 线边界与错误锚词（实现补充）

单包 payload 上界为 1472（固定头+cookie+options）；跨 MSS 分段由 UDP/IP 框架负责，DHCP builder 不自行分段。边界覆盖应包括 hlen 0/6/16、sname 64、file 128、option 字段 255、options 1232 及相邻值。validator 错误锚词包括 `DHCPv4 requires IPv4 addresses`、`invalid DHCP role`、`DHCP messages is required`、`unknown DHCP message type`、`HType=1 requires HLen=6`、`options exceed MTU`、`option overload not supported`、`option 255 END is reserved`、`invalid direction`、`client must have empty giaddr`。ctx 取消或 EmitMsg 错误直接返回。

## 12. 覆盖反查建议

建议 coverage gate 静态检查：链顺序 `[udp,dhcp]`；scenario=dora 产 4 包；四包 xid 同值；option 53 值 1/2/3/5；yiaddr/server-id/MAC 与 spec；默认端口与广播；validator 负例锚词；固定头 offset 0/4/10/12/16/28；options 长度上限；缺省空 dhcp 产 DISCOVER。当前 cases 仅证明 DORA，不应申报其余建议项已过。

## 13. 缺口登记

| ID | 现象 | 证据 | 归属阶段 |
|---|---|---|---|
| G-DHCP-1 | 仅 DORA case，NAK/release/inform/renew/rebind 无机器断言 | `cases/dhcp.json` 只有 `dhcp_smoke_01` | 用例覆盖阶段 |
| G-DHCP-2 | 动态策略字段与按流序号算法未接入 | `layer_gen.go:83-85` 仅随机 xid | 生成器阶段 |
| G-DHCP-3 | IPv6、非默认端口、relay、多会话/并发未覆盖 | validator 明确拒 IPv6；单 flow event loop | 用例覆盖阶段 |
| G-DHCP-4 | options/长度/截断/非法 type 负例未进入 cases | 当前 JSON 无 `expect_error` | 用例覆盖阶段 |
| G-DHCP-5 | tracked 结果产物过期：末次提交 `a674fe96`（2026-09-05）早于 `0417be5`（2026-09-13），pcap 留档目录不存在 | `git log -1 -- trafficgen/docs/protocol-pcap-test/dhcp.md`；目录 `ls` 无 | 产物阶段（P5 重跑后重生成） |

## 14. 门1 §1–§14 对照表

| 门 | 满足方式与证据 |
|---|---|
| §1 顶层旧键 | 逐键去向见 §1（DHCP 业务键全部入 `spec.DHCP` 层内；flow 地址/端口按元数据语义消费）；目标形状完整 spec_json 样例见 §1 |
| §2 规范基线 | RFC 2131 DHCPv4/BOOTP+UDP，见 §1/§3 |
| §3 五件套 | 会话表/事务序列/关联关系/插入位置/时间线完整见 §2 |
| §4 消息与状态机 | 消息类型 1..8、scenario 六种、manual messages 见 §4 |
| §5 线格式 | 固定头、cookie、TLV、offset/端序/长度公式见 §3 |
| §6 代码路径 | validator、planner、builder、layer generator 路径见 §6 |
| §7 五层覆盖 | 五层覆盖矩阵与缺口见 testcase §3；IPv6 生成路径由 validator 拒绝，理由见 §5；业务多流见 §2 |
| §8 地址与流 | 端口/IP/MAC/广播/relay 见 §5 |
| §9 性能 | 性能边界与 options 上限见 §6；反查建议见 §12 |
| §10 错误处理 | 错误锚词与失败传播见 §11 |
| §11 规范依据 | RFC 2131 §2、§3.1、§4.1、§4.3，见 §1/§4 |
| §12 动态字段 | 四元组与业务字段清单、xid 随机与 packet index 算法、待实现边界见 §8 |
| §13 双输出 | pcap 与 NIC 共用同一 layer/event 契约；NIC 输出需主线程实测，见 §5/§9 |
| §14 缺口登记 | 缺口与待实现边界集中登记于 §13，不计入已覆盖行为 |

## 15. 复核记录

自审 3 轮，末轮干净：机读复核 cases ID/包数/21 条 field 断言、门1 十四行、缺口三要素、过期产物提交号与目录缺失；人工复核线格式 offset/端序与代码行号引用。

## 16. 术语与参考

xid=DHCP transaction ID；chaddr=client hardware address；yiaddr=your IP；ciaddr=client IP；giaddr=relay agent IP；DORA=Discover/Offer/Request/ACK。规范：RFC 2131；实现：`trafficgen/internal/protocol/dhcp/{planner.go,scenario.go,layer_gen.go}`。

## 17. 过期产物与修订记录

`trafficgen/docs/protocol-pcap-test/dhcp.md` 是 tracked 结果产物，末次提交 `a674fe96`（2026-09-05）早于扁平判死基线 `0417be5`（2026-09-13），且其链接的 `trafficgen/docs/protocol-pcap-test/dhcp/` 目录当前不存在；登记为过期产物，不作为当前复跑证据。归属代码/产物阶段：重跑套件后重生成。

## 18. D/T/C 三方对账

| 维度 | design（本文件） | testcase | cases JSON | 结论 |
|---|---|---|---|---|
| ID 集合 | `dhcp_smoke_01`（§12） | `dhcp_smoke_01`（§2） | `dhcp_smoke_01`（1 例） | 一致 |
| 配置形状 | §1 的 `spec_json` 顶层仅 `layers`，DHCP 业务配置位于 `layers[].dhcp` | §2 声明 `[udp,dhcp]` | 顶层仅 `layers`，层序 `[udp,dhcp]` | 一致 |
| 包数 | DORA 4 包（§4） | 4 | `packet_count=4` | 一致 |
| 断言 | §3–§5 规定 op/options/地址/MAC/XID | §2 枚举 21 条 field 断言及 3 条 XID 关联 | 21 条 field 条目，XID 2/3/4 `same_as_packet:1` | 一致 |
| 未实现/未覆盖 | G-DHCP-1…5 与动态、relay、负例边界明确排除 | 同号缺口与反查建议 | 当前无负例、无额外场景 ID | 不冒充已覆盖 |

严格层链迁移结论：旧形状中的游离顶层 `dhcp` 映射已迁入 `layers[1].dhcp`；当前 cases 不保留 `spec_json.dhcp`，也不以空壳层条目代替已声明的 DORA 配置。空配置默认 DISCOVER 仍是实现能力边界，当前 JSON 未将其冒充为独立覆盖。

## 19. 修订记录