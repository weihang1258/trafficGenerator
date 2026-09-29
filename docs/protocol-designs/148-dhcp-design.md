# DHCPv4 设计契约（as-built）

## 1. 范围、规范与目标形状

实现是 DHCPv4（RFC 2131；BOOTP wire format 由 RFC 2131 §2/§4.1 定义）终结层，承载于 UDP。配置唯一真相是层链；完整严格目标形状必须把链路、网络、传输和业务字段分别放入对应层：

```json
{"layers":[{"eth":{"src_mac":"02:00:00:00:00:01","dst_mac":"ff:ff:ff:ff:ff:ff"}},{"ip":{"src":"0.0.0.0","dst":"255.255.255.255","ttl":64}},{"udp":{"src_port":68,"dst_port":67}},{"dhcp":{"scenario":"dora","default_your_ip":"192.168.1.100","default_server_identifier":"192.168.1.1"}}]}
```

门1 §1 旧形逐键去向：`src_mac/dst_mac` 进入 `eth`，`src_ip/dst_ip/ttl` 进入 `ip`，`src_port/dst_port` 进入 `udp`；`role`、`xid`、`scenario`、`messages`、`client_mac`、`h_type`、`h_len`、`broadcast_flag`、`secs`、`sname`、`file`、全部 `default_*` 及 message 内 `type/direction/client_ip/your_ip/server_ip/relay_agent_ip/hops/server_identifier/lease_time/t1/t2/subnet_mask/routers/dns/domain_name/hostname/domain_search/client_id/requested_ip/param_request_list/vendor_class/relay_agent_info/extra_options/broadcast` 均由 `strategy_convert.go:2586-2694` 解析进 `spec.DHCP`，目标位置是层链 `layers[].dhcp`（或同一 `DHCPConfig` 的 `messages[]`）。`count/bps/duration` 由 flow control 处理。当前实现/可执行 case 尚未完成上述 eth→ip→udp→dhcp 全链迁移；不得把 flow metadata 当作合规层链字段或声称 Gate 1 §1 已通过。

`dhcp` 缺省时生成一个 DISCOVER。`scenario` 可为 `dora|nak|release|inform|renew|rebind`，非 scenario 使用 `messages[]` 原样逐条发包。

## 2. 业务场景与五件套

现网基线是客户端获取租约（DORA）、拒绝（NAK）、释放、INFORM、续租和重绑定。一个 DHCP 会话由同一四元组和同一 xid 关联；每条消息是一个 UDP datagram，按配置顺序发出。单流协议，不适用多流；多会话/并发调度不是当前 DHCP layer 的能力，需上层重复 flow 承载并分别分配 flow ID。

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

## 5. 地址、端口与承载

client 默认 68→67，server 默认 67→68，relay 默认 67→67；显式 flow 端口优先。缺省 IPv4 为 client/server/relay 的 `0.0.0.0` 到 `255.255.255.255`，缺省目标 MAC 为广播。广播消息强制目标 IP/MAC 广播；down 事件交换 IP/MAC，server 缺省源 MAC 为 `02:00:00:00:00:02`。DHCPv4 validator 拒绝 IPv6。事件携带 `SrcPort/DstPort`、`L4PortOverride=true`、TTL（默认 64）、目标 IP/MAC 覆盖，UDP 层输出一个 datagram/event。

## 6. 配置到输出路径

JSON `strategy_convert.go:2586-2694` 解析 `DHCPConfig`、`DHCPMessage` 和 extra options；registry 以 `dhcp` 取 validator/generator。validator `planner.go:100-387` 检查 IPv4、角色、消息 type、字段长度、MAC、HType/HLen、sname/file、options 上限、relay 与保留 option。planner `Plan` 与 `DHCPGenerator.Generate` 共用 builder 语义；`buildDHCPMessage:788-825` 拼接 payload，`encodeBootpHeader:829-910` 编码固定头，`encodeOptions:915+` 编码 TLV。

## 7. 动态字段与序号

当前 DHCP layer 的协议关键字段为 `xid`、client MAC、地址、端口及消息字段。`xid=0` 使用 `rand.Uint32()`，不是按流序号递增；消息 packet index 从 0 起并由数组索引产生（`layer_gen.go:201`）。策略 fixed/inc/rand/list/pattern 的统一动态策略接线不在 DHCP generator 内；故 N 流动态展开、回绕、随机 seed、pattern、静态重复拒绝均为待实现边界，不将其冒充已覆盖。

## 8. 性能、边界与错误

单包 payload 上界为 1472（固定头+cookie+options）；跨 MSS 分段由 UDP/IP 框架负责，DHCP builder 不自行分段。边界覆盖应包括 hlen 0/6/16、sname 64、file 128、option 字段 255、options 1232 及相邻值。validator 错误锚词包括 `DHCPv4 requires IPv4 addresses`、`invalid DHCP role`、`DHCP messages is required`、`unknown DHCP message type`、`HType=1 requires HLen=6`、`options exceed MTU`、`option overload not supported`、`option 255 END is reserved`、`invalid direction`、`client must have empty giaddr`。ctx 取消或 EmitMsg 错误直接返回。

## 9. 覆盖反查建议

建议 coverage gate 静态检查：链顺序 `[udp,dhcp]`；scenario=dora 产 4 包；四包 xid 同值；option 53 值 1/2/3/5；yiaddr/server-id/MAC 与 spec；默认端口与广播；validator 负例锚词；固定头 offset 0/4/10/12/16/28；options 长度上限；缺省空 dhcp 产 DISCOVER。当前 cases 仅证明 DORA，不应申报其余建议项已过。

## 10. 缺口登记

| ID | 现象 | 证据 | 归属阶段 |
|---|---|---|---|
| G-DHCP-1 | 仅 DORA case，NAK/release/inform/renew/rebind 无机器断言 | `cases/dhcp.json` 只有 `dhcp_smoke_01` | 用例覆盖阶段 |
| G-DHCP-2 | 动态策略字段与按流序号算法未接入 | `layer_gen.go:83-85` 仅随机 xid | 生成器阶段 |
| G-DHCP-3 | IPv6、非默认端口、relay、多会话/并发未覆盖 | validator 明确拒 IPv6；单 flow event loop | 用例覆盖阶段 |
| G-DHCP-4 | options/长度/截断/非法 type 负例未进入 cases | 当前 JSON 无 `expect_error` | 用例覆盖阶段 |
| G-DHCP-5 | tracked 结果产物过期：末次提交 `a674fe96`（2026-09-05）早于 `0417be5`（2026-09-13），pcap 留档目录不存在 | `git log -1 -- trafficgen/docs/protocol-pcap-test/dhcp.md`；目录 `ls` 无 | 产物阶段（P5 重跑后重生成） |
| G-DHCP-6 | executable case 仍将 `dhcp` 及 eth/ip/udp 承载字段放在层链外或依赖 flow metadata，未满足完整 eth→ip→udp→dhcp 层链唯一真相/顶层白名单 | `trafficgen/test/protocol_pcap/cases/dhcp.json:6-19`；目标形见本稿 §1；现状承载路径见 §5–§6 | 配置迁移阶段（迁移后重跑） |
| G-DHCP-7 | scenario validator 只预检 `synthesized[0]`，后续消息 options 超限要到 builder 才失败 | `planner.go:349-371,819-823`；本稿 §8；testcase §6 | validator/用例阶段（逐消息预检并补负例） |

## 11. 门1 §1–§14 对照表

证据编号严格对应 `docs/CORE_MEMORY.md` 与 `protocol-doc-requirements` 的 §1–§14；“缺口”表示不能作为已满足证据。

| 门 | 本协议满足方式与精确证据 | 状态 |
|---|---|---|
| §1 层链唯一真相与旧键退出 | 严格目标形为 `eth→ip→udp→dhcp`，字段去向见 §1；但 executable case 与当前承载路径仍依赖层链外 DHCP/flow metadata（G-DHCP-6）。 | 缺口 |
| §2 策略/任务分工与封包 | DHCP 作为单策略单 flow，数量/速率由 flow control 处理见 §1、§2；未有任务级多策略/封顶用例。 | 部分，缺口 |
| §3 多会话/事务/多流关联 | 单流协议豁免多流；会话表、DORA/其他序列、关联、插入位置、时间线见 §2。多会话/并发与异常编排未覆盖（G-DHCP-3）。 | 部分，缺口 |
| §4 规范先行与三路对照 | RFC 2131 §2/§3.1/§4.1/§4.3 依据见 §1–§5；商业行为与可靠开源实现的逐条对照及候选方案表未提供。 | 缺口 |
| §5 有依据设计与错误处理 | 依赖、错误锚词、失败传播见 §6、§8；options 后续消息预检缺口见 G-DHCP-7，负例未进入 cases（G-DHCP-4）。 | 部分，缺口 |
| §6 性能设计与双路验收 | payload/options 上限与 builder 路径见 §8；pcap/NIC 验收要求见 §9，但吞吐、并发、内存、队列、CPU 目标及实测缺失。 | 缺口 |
| §7 三份权威文档关系 | 本稿与 testcase 回指 cases 机器来源，见 testcase §1–§2；`docs/CODE_DESIGN.md`/`docs/TEST_CASES.md` 的统一登记映射未提供。 | 缺口 |
| §8 设计先行八要素 | 接口/数据/流程/错误/边界见 §2–§8；明确改文件、冲突点与回滚方式未形成八要素清单。 | 缺口 |
| §9 三源测试与颗粒度 | testcase §2–§6 列出现有 DORA 与缺口；规范逐字段/错误码全表、动态整格、复杂业务矩阵尚未形成可执行用例（G-DHCP-1/2/4）。 | 部分，缺口 |
| §10 改后评审闭环 | 本稿 §12 记录自审；真实流程全量、负例、`-race` 等闭环证据未提供。 | 缺口 |
| §11 白话表达 | 术语表见 §13；本门仅记文档证据，未替代功能/测试证据。 | 已具备文档证据 |
| §12 动态字段与序号算法 | 字段清单、xid 随机及 packet index 算法见 §7；fixed/inc/rand/list/pattern 与按流确定性算法未接入（G-DHCP-2）。 | 部分，缺口 |
| §13 schema 单一机器契约 | 目标层链见 §1；DHCP 专属 schema/统一校验入口与生成同步证据未提供，且 case 仍为旧形（G-DHCP-6）。 | 缺口 |
| §14 MCP 真实流程验收 | testcase 记录 machine case 来源与字段断言；MCP 建任务→真实生成→tshark、负例和全量重跑证据未提供，旧产物过期（G-DHCP-5）。 | 缺口 |

## 12. 复核记录

自审 3 轮，末轮干净：机读复核 cases ID/包数/21 条 field 断言、门1 十四行、缺口三要素、过期产物提交号与目录缺失；人工复核线格式 offset/端序与代码行号引用。

## 13. 术语与参考

xid=DHCP transaction ID；chaddr=client hardware address；yiaddr=your IP；ciaddr=client IP；giaddr=relay agent IP；DORA=Discover/Offer/Request/ACK。规范：RFC 2131；实现：`trafficgen/internal/protocol/dhcp/{planner.go,scenario.go,layer_gen.go}`。

## 14. 过期产物与修订记录

`trafficgen/docs/protocol-pcap-test/dhcp.md` 是 tracked 结果产物，末次提交 `a674fe96`（2026-09-05）早于扁平判死基线 `0417be5`（2026-09-13），且其链接的 `trafficgen/docs/protocol-pcap-test/dhcp/` 目录当前不存在；登记为过期产物，不作为当前复跑证据。归属代码/产物阶段：重跑套件后重生成。

本稿为 as-built 文档；未改代码、cases 或 gate。