# BGP（边界网关协议，Border Gateway Protocol）测试用例设计

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/36-bgp-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/bgp.json`  
> 状态：`bgp` 层尚未实现；本文定义实现后的 PCAP（抓包文件）断言，不宣称当前 MCP（模型上下文协议）套件可运行。

## 1. 测试原则与固定事实

用例从设计 §1（证据等级/profile）、§2（TCP/179 与配置）、§3（RFC 4271 线格式）、§4（邻接状态）、§5（IPv6 transport/MP_REACH 边界）和 §7（错误处理）逐项派生。

- 正例必须有 `packet_count`、TCP 握手/正常终止断言；除纯 `connect` 外必须有至少一个 `fields` 或 `frames` observable（可观察断言）。
- 负例的 `expect` 严格只有 `expect_error` 与 `error_contains`，不对失败 PCAP 作断言。
- 无额外 TCP option 且每个事件单独一个 data segment（数据段）时，`packet_count = 3 + 应用事件数 + 4`；多 session 按每条 TCP 四元组独立计算后求和。
- IPv4 应用 payload（载荷）起点为 offset（偏移）54；IPv6 起点为 74。offset 仅用于实际未分段帧；MSS（最大报文段长度）分段必须通过 TCP stream（TCP 流）重组验证。
- 所有正例显式使用 `wire_profile=bgp_rfc4271_ipv4_unicast`。IPv6 transport 仍使用 IPv4 NLRI（网络层可达性信息）profile，不等于 MP_REACH（多协议可达性）支持。

## 2. 用例索引

| # | ID | 类型 | 覆盖 | 应用事件/每流 | 包数 |
|---:|---|---|---|---:|---:|
| 1 | `bgp_connect` | 正 | TCP/179 connect（连接）且无隐式应用报文 | 0 | 7 |
| 2 | `bgp_open_keepalive` | 正 | OPEN、双向 KEEPALIVE | 4 | 11 |
| 3 | `bgp_update_attributes` | 正 | UPDATE + ORIGIN/AS_PATH/NEXT_HOP/MED/LOCAL_PREF/COMMUNITIES | 5 | 12 |
| 4 | `bgp_update_withdraw` | 正 | withdrawn route（撤销路由）IPv4 /24 | 5 | 12 |
| 5 | `bgp_notification_hold_expired` | 正 | NOTIFICATION Hold Timer Expired | 3 | 10 |
| 6 | `bgp_hold_time_zero` | 正 | OPEN hold time=0 | 4 | 11 |
| 7 | `bgp_ipv4_nlri_32` | 正 | IPv4 /32 NLRI 字节边界 | 5 | 12 |
| 8 | `bgp_ipv6_transport` | 正 | IPv6 TCP transport + IPv4 BGP identifier | 4 | 11 |
| 9 | `bgp_multi_session` | 正 | 两个独立四元组会话 | 4×2 | 22 |
| 10 | `bgp_keepalive_length_boundary` | 正 | 合法最小 length=19 KEEPALIVE | 4 | 11 |
| 11 | `bgp_neg_udp` | 负 | UDP carrier（承载） | — | — |
| 12 | `bgp_neg_mp_reach_profile` | 负 | 未实现 MP_REACH IPv6 profile | — | — |
| 13 | `bgp_neg_marker` | 负 | marker 非全 `0xff` | — | — |
| 14 | `bgp_neg_length` | 负 | length 小于 19 | — | — |
| 15 | `bgp_neg_type` | 负 | 未知 type=9 | — | — |
| 16 | `bgp_neg_version` | 负 | OPEN version=3 | — | — |
| 17 | `bgp_neg_as` | 负 | My AS 超出两字节范围 | — | — |
| 18 | `bgp_neg_state` | 负 | OPEN 前 UPDATE | — | — |
| 19 | `bgp_neg_address` | 负 | IPv4 profile 中出现 IPv6 NLRI | — | — |

## 3. 正向用例

### 3.1 `bgp_connect`（S1）

使用 TCP/179、IPv4、空 `events`。预期 7 包（SYN、SYN-ACK、ACK、四步 FIN 终止），`has_payload=false`。证明 planner 不隐式插入 OPEN 或 KEEPALIVE。

### 3.2 `bgp_open_keepalive`（S2）

事件为 c2s OPEN（version=4、AS=64512、hold=90、identifier=192.0.2.1）、s2c OPEN（AS=64513、identifier=192.0.2.2）、双向 KEEPALIVE。预期 11 包。packet 4/5 的 `bgp.type=1`，packet 4 的 `bgp.open.version=4`，packet 6/7 的 `bgp.type=4`；四帧在 offset 54 分别锚定 RFC 4271 marker、length、type。OPEN optional parameters length=0，不编造 capability（能力）字节。

### 3.3 `bgp_update_attributes`（S3）

在 S2 事件后发送 c2s UPDATE，NLRI 为 `203.0.113.0/24`，属性为 ORIGIN=IGP、AS_PATH=[64512]、NEXT_HOP=192.0.2.1、MED=100、LOCAL_PREF=100、COMMUNITIES=[NO_EXPORT]。预期 12 包，packet 8 `bgp.type=2`，withdrawn length=0，path attributes length=39，属性和 prefix length=24 均可观察；offset 54 的 frame 固定为 66 字节 BGP UPDATE（长度字段 `00 42`）。

### 3.4 `bgp_update_withdraw`（S4）

在 S2 后发送仅撤销 `203.0.113.0/24` 的 UPDATE，withdrawn routes length=4，path attributes length=0，NLRI 为空。预期 12 包；packet 8 断言 type=2、withdrawn length=4、path attributes length=0、prefix length=24，并锚定 `00 1b 02 00 04 18 cb 00 71 00 00`。

### 3.5 `bgp_notification_hold_expired`（S5）

OPEN 双向交换后由 s2c 发送 NOTIFICATION code=4、subcode=0（Hold Timer Expired），随后 TCP 终止。预期 10 包；packet 6 断言 type=3、major error=4、expired subcode=0，固定 21 字节报文（length=21）。NOTIFICATION 是合法应用事件，不应被当成 planner error（规划器错误）。

### 3.6 `bgp_hold_time_zero`（S6）

c2s OPEN 的 hold time 显式为 0，s2c OPEN 保持 90，随后双向 KEEPALIVE。预期 11 包；packet 4/5 分别断言 holdtime=0/90，packet 6/7 为 type=4，frame 只锚定 packet 4 的零 hold time 和 packet 6 的最小 KEEPALIVE。

### 3.7 `bgp_ipv4_nlri_32`（S7）

S2 后发送 `192.0.2.1/32` NLRI 与同一组基础属性。预期 12 包；packet 8 断言 type=2、prefix_length=32，并固定 NLRI 尾部 `20 c0 00 02 01`，守护 prefix length 到 4 个地址字节的边界。

### 3.8 `bgp_ipv6_transport`（S8）

src/dst 使用 `2001:db8::1/2001:db8::2`，TCP 仍目的端口 179；事件为 S2。预期 11 包；packet 4 `ipv6.version=6`、`tcp.dstport=179`、`bgp.open.identifier=192.0.2.1`，frame offset 改为 74。该例不出现 IPv6 NLRI 或 MP_REACH 属性。

### 3.9 `bgp_multi_session`（S9）

两个 session 的源端口为 12345/12346，各自执行 S2 的四个事件，预期 22 包。只用聚合 `distinct_values` 断言 `tcp.srcport` 为 12345/12346、`tcp.dstport` 为 179，不假设调度器交织顺序；每条四元组必须拥有独立 OPEN 状态。

### 3.10 `bgp_keepalive_length_boundary`（S10）

重复 S2，packet 6 断言 `bgp.length=19`、`bgp.type=4`，并固定完整 19 字节 KEEPALIVE。该值是 RFC 4271 合法下界，不是截断报文。

## 4. 负向用例

负例只验证配置在 planner/validator 层拒绝，并要求错误关键词稳定传播到任务错误终态：

| ID | 输入 | `error_contains` |
|---|---|---|
| `bgp_neg_udp` | `layers=[udp,bgp]` | `tcp` |
| `bgp_neg_mp_reach_profile` | `wire_profile=bgp_mp_reach_ipv6_pending` | `profile` |
| `bgp_neg_marker` | `wire_fault.fault_kind=marker` | `marker` |
| `bgp_neg_length` | `wire_fault.fault_kind=length,value=18` | `length` |
| `bgp_neg_type` | `wire_fault.fault_kind=type,value=9` | `type` |
| `bgp_neg_version` | OPEN version=3 | `version` |
| `bgp_neg_as` | OPEN My AS=70000 | `as` |
| `bgp_neg_state` | 首个事件为 UPDATE | `state` |
| `bgp_neg_address` | IPv4 profile 的 NLRI=`2001:db8::/32` | `address` |

`wire_fault` 是测试注入入口，不是合法 BGP 线上字段；不得把损坏的 marker、length 或 type 生成为“成功” PCAP。MP_REACH、能力协商、4-octet ASN 和认证均必须以新 profile 承载，不能放宽当前负例。

## 5. 三方一致性检查

1. 本文、设计 §6/§7 与 JSON 的 19 个 ID 集合和顺序一致；正例 10 个、负例 9 个。
2. 正例包数严格为 `[7,11,12,12,10,11,12,11,22,11]`；负例没有 `packet_count`、`fields` 或 `frames`。
3. 正例除 `bgp_connect` 外均 `has_payload=true` 且有 observable；全部正例 `has_handshake=true`、`terminates=true`。
4. IPv4 frame offset 仅为 54；IPv6 transport 例仅为 74。所有固定 frame 均从 BGP marker 起点开始，未把 TCP/IP 头当作应用字节。
5. 四字节前缀、属性长度、总 BGP length、KEEPALIVE 19 字节和 NOTIFICATION 21 字节均可由 RFC 4271 逐字节复算；IPv6 MP_REACH 没有伪造 hex。
6. 多 session 只用调度无关的 distinct port assertion；不使用固定 packet 序号绑定不同 session 的事件。

## 6. 实现后执行建议

先运行 JSON 语法、ID 唯一性、正负 expect 结构和 frame hex 长度静态检查；层注册后依次跑 connect、OPEN/KEEPALIVE、UPDATE/NOTIFICATION、IPv6 transport、多 session，再确认九个负例都由 task error 终态通过。取得 RFC 4760/RFC 5492/RFC 6793 的实现 profile 后，另行增加 MP_REACH、capability 和 4-octet ASN 用例，不修改本套件的 IPv4 基础契约。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 10 个正例和 9 个负例，覆盖 RFC 4271 基础报文、状态、IPv4/IPv6 transport、多 session、边界与错误路径；明确 MP_REACH 待实现边界。
