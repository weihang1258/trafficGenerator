# DHCPv4 设计契约（as-built）

## 1. 范围、规范与目标形状

实现是 DHCPv4（RFC 2131；BOOTP wire format 由 RFC 2131 §2/§4.1 定义）终结层，承载于 UDP。配置唯一真相是层链：`{"layers":[{"udp":{}},{"dhcp":{}}],"dhcp":{"scenario":"dora","default_your_ip":"192.168.1.100","default_server_identifier":"192.168.1.1"}}`。旧顶层 flow 地址/端口仍作为 flow 元数据输入，由 `resolvePorts/resolveIPs/resolveMACs` 读取；DHCP 业务字段不再游离到顶层。

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
| G-DHCP-5 | tracked `trafficgen/docs/protocol-pcap-test/dhcp.md` 为旧产物，早于扁平判死基线时应重生成 | git tracked artifact，需主线程核验提交时间 | 文档/产物阶段 |

## 11. 门1 §1–§14 对照表

| 门 | 满足方式与证据 |
|---|---|
| §1 | 顶层旧键去向与完整层链目标形见 §1；解析见 strategy_convert:2586 |
| §2 | RFC 2131 DHCPv4/BOOTP+UDP，见 §1/§3 |
| §3 | 会话表、事务序列、关联、插入位置、时间线完整见 §2 |
| §4 | 消息类型 1..8、scenario 六种、手工 messages 见 §4 |
| §5 | 固定头、cookie、TLV、offset/端序/长度公式见 §3 |
| §6 | validator、planner、builder、layer generator 路径见 §6 |
| §7 | 五层覆盖分别见 testcase §4；不适用 IPv6 生成见 §5，业务多流见 §2 |
| §8 | 端口/IP/MAC/广播/relay 见 §5 |
| §9 | 性能边界与 options 上限见 §8；反查建议见 §9 |
| §10 | 错误锚词与失败传播见 §8 |
| §11 | 规范依据 RFC 2131 §2、§3.1、§4.1、§4.3，见 §1/§4 |
| §12 | 动态字段四元组（src/dst IP/port）及业务字段 xid/MAC/message fields、随机算法与 packet index 见 §7 |
| §13 | pcap 与 NIC 共用同一 layer/event 契约；NIC 输出需主线程实测，见 §5/§9 |
| §14 | 缺口与待实现边界集中登记于 §10，不计入已覆盖行为 |

## 12. 复核记录

自审 2 轮，末轮干净：已回对目标形状、cases ID/包数/断言、实现行号、字段 offset/端序、门1 十四行与缺口三要素。

## 13. 术语与参考

xid=DHCP transaction ID；chaddr=client hardware address；yiaddr=your IP；ciaddr=client IP；giaddr=relay agent IP；DORA=Discover/Offer/Request/ACK。规范：RFC 2131；实现：`trafficgen/internal/protocol/dhcp/{planner.go,scenario.go,layer_gen.go}`。
