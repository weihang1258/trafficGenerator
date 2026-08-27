# BACnet（楼宇自动化通信协议，Building Automation and Control Network）设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 状态：仅设计与 PCAP（抓包文件）/NIC（网卡）用例契约；`bacnet` 层尚未注册，不修改 Go（编程语言）/MCP（模型上下文协议）实现，不宣称当前 suite（测试套件）可运行。  
> 配套文件：`docs/protocol-designs/65-bacnet-testcase.md`、`trafficgen/test/protocol_pcap/cases/bacnet.json`  
> 任务编号：65（B6 协议任务；64 为 Stratum，66 为待生成 DOH）  
> 规范基线：ANSI/ASHRAE 135（BACnet 标准）、BACnet/IP、BACnet/IPv6 与 BACnet/TCP 相关章节；默认 BACnet/IP UDP 端口 47808（0xBAC0）。

## 1. 范围、证据等级和未注册边界

本契约覆盖以太网（Ethernet）帧、BVLC（BACnet Virtual Link Control，BACnet 虚拟链路控制）、NPDU（Network Protocol Data Unit，网络协议数据单元）和 APDU（Application Protocol Data Unit，应用协议数据单元）的逐层编码，以及 confirmed/unconfirmed service（确认/未确认服务）、分段、事务关联、对象/属性、Who-Is/I-Am、ReadProperty/WriteProperty、COV（Change of Value，值变化）订阅通知、Error/Reject/Abort（错误/拒绝/中止）、UDP 广播与 BBMD（BACnet Broadcast Management Device，BACnet 广播管理设备）、foreign-device（外部设备）登记、BACnet/TCP 封帧、IPv4/IPv6、多会话/多流和 PCAP/NIC 观察。

没有真实设备数据库、设备实例分配、时间同步或 BBMD 部署证据时，只断言编码字段、方向、长度、服务选择、对象/属性枚举、动态字段存在及同一会话内关联；不得声称设备真实在线、属性值真实、时间有效、COV 已被现场接受、BBMD 已转发到真实网络，或 BACnet/SC（安全连接）/TLS（传输层安全）已经建立。运行期 `transaction_id`（事务标识）、`invoke_id`（调用标识）、对象实例、序列号、时间戳、COV 值和网络地址使用 `presence`（存在）、`nonzero`（非零）、`same_as_packet`（与指定包相同）、`distinct`（彼此不同）及类型/长度断言，禁止硬编码具体动态值。

当前仓库没有注册 `bacnet` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/bacnet.json` 只能保留一个 `bacnet_neg_unregistered` 注册前置占位，必须 `expect_error=true` 且 `error_contains="unknown layer"`；占位不计入下文 20 个语义 ID。注册前被拒绝、0 包或空 PCAP 不是 BACnet 行为通过。

## 2. 推荐配置、层链和载体边界

推荐最小层链为 `[udp, bacnet]`，由 planner 自动补全所需 IP 层；实现后建议配置形态如下：

```json
{
  "layers": [{"udp": {}}, {"bacnet": {}}],
  "src_ip": "192.0.2.66",
  "dst_ip": "198.51.100.66",
  "src_port": 47808,
  "dst_port": 47808,
  "bacnet": {
    "network": "bip",
    "bvlc_function": "original-unicast-npdu",
    "npdu": {"version": 1, "expecting_reply": true},
    "apdu": {"kind": "confirmed-request", "service": "read-property"}
  }
}
```

| 配置项 | 约束 |
|---|---|
| `network` | `bip`（BACnet/IP）为默认；`bip-broadcast`、`bip-bbmd`、`bip-foreign-device`、`bip6`、`tcp` 仅在对应正例显式声明。BACnet/SC/TLS 本期不实现，只能作为不透明 carrier（载体）边界。 |
| `src_ip`/`dst_ip` | IPv4 fixture（固定样本）使用 `192.0.2.66`/`198.51.100.66`；IPv6 使用文档另行声明的文档地址，不从 IPv4 fixture 继承。 |
| 端口 | BACnet/IP 默认 UDP 47808；BACnet/TCP 使用显式 TCP 端口与长度封帧。错误载体、端口或协议族不得被 planner 静默修正。 |
| `bvlc_function` | `original-unicast-npdu`、`original-broadcast-npdu`、`forwarded-npdu`、`register-foreign-device`、`read-broadcast-distribution-table` 等必须与网络场景一致；BVLC version/type/length/function 不可缺省伪造。 |
| `npdu` | 版本、控制位、DNET/DADR、SNET/SADR、Hop Count、网络层消息类型及优先级按字段存在和边界编码；目的/源网络地址出现时必须与控制位一致。 |
| `apdu` | `confirmed-request`、`unconfirmed-request`、`simple-ack`、`complex-ack`、`segment-ack`、`error`、`reject`、`abort`；确认请求必须有动态 invoke ID，响应必须在同一会话相关联。 |
| `object`/`property` | 对象类型、对象实例、属性标识、数组索引和 application tag（应用标签）按规范编码；实例/值/时间为动态或 fixture 字段，不写固定运行期值。 |
| `sessions`/`flows` | 每会话独立 transaction/invoke、设备实例、COV subscription（订阅）和重组缓存；全局交织包序不可替代流内关联。 |
| `wire_fault` | 仅负例注入口：`length-version`、`npdu-apdu`、`object-property`、`carrier-port`、`family-bbmd`、`transaction`。 |

## 3. Ethernet、BVLC 和 NPDU 编码

Ethernet fixture 默认使用 IPv4/UDP，EtherType、源/目的 MAC、可选 VLAN（虚拟局域网）边界必须位于 IP 之前；PCAP 断言应先验证 Ethernet→IP→UDP 的方向、地址、端口，再解析 BACnet。VLAN 只有在明确 fixture 中出现，不能从普通以太网样本推断。

BACnet/IP 的 BVLC 基本结构为 `BVLC type`、`function`、`length` 和后续 NPDU。常见 type 为 `0x81`；original-unicast-NPDU、original-broadcast-NPDU、forwarded-NPDU、foreign-device 登记/分发表操作使用各自 function，length 是从 BVLC 起始到整个 NPDU 的编码字节数。`length` 必须覆盖真实 BVLC+NPDU，不能用 UDP payload 之外的字节、Unicode 字符数或下层帧总长替代。

NPDU version 通常为 `0x01`。控制八位组的 destination-specified、source-specified、出站网络层消息、expecting-reply 和 priority 位决定后续字段是否存在：目的网络号/地址、源网络号/地址、Hop Count、网络层消息类型必须按位出现并逐项消耗。网络层消息与普通 APDU 互斥；广播 NPDU 的目的语义、BBMD 转发的原始地址包装和 Hop Count 必须可区分。

BBMD/foreign-device 仅测试报文边界和配置语义：foreign device 的登记、TTL（生存时间）、广播分发和 forwarded-NPDU 的原始地址字段可观察，但没有真实 BBMD 不声称已完成跨子网转发。UDP 广播 fixture 不得把单播响应伪造为广播；广播响应/设备发现的方向和广播 MAC/IP 由具体场景声明。

## 4. APDU、服务和事务关联

APDU 的 PDU type（协议数据单元类型）必须和服务形态匹配：confirmed-request、unconfirmed-request、simple-ack、complex-ack、segment-ack、error、reject、abort 使用规范首字节的类型/标志位；confirmed request 还携带动态 invoke ID、服务选择和服务参数，响应必须复用 invoke ID。`transaction_id` 在 BACnet/IP 传输/事务 fixture 中如被使用同样只作动态存在和同会话关联，不能固定为某个数值；不能把 TCP sequence 或 UDP 端口当作 invoke ID。

覆盖的服务至少包括：

- Who-Is（未确认设备发现）与 I-Am（未确认设备应答）：断言设备实例范围、最大 APDU 长度、分段能力和 vendor identifier 的 application tag/类型；实例和厂商值动态化。
- ReadProperty（确认读取属性）：断言 object identifier、property identifier、可选 array index、成功 complex-ack 与 application value tag；响应对象/属性必须与请求匹配。
- WriteProperty（确认写入属性）：断言 object/property、priority（优先级）、application value 和成功 simple-ack/错误路径；不声称现场值被持久化。
- SubscribeCOV（确认 COV 订阅）与 COVNotification（未确认或确认通知）：断言 subscriber/process identifier、object identifier、issue-confirmed-notifications、lifetime 和 property value；lifetime 与时间戳动态，不硬编码时间。
- Error、Reject、Abort：断言错误 class/code、拒绝原因、分段/资源/安全原因的 context/application tag 和关联 invoke ID；失败响应不能伪造成成功 ACK。

Confirmed service 的 segmentation（分段）通过 more-follows、sequence number、proposed window size 和 segment-ack 关联；段边界不等于 UDP 包边界，重组后服务选择和字段只能出现一次。Unconfirmed service 不携带确认事务的 invoke 语义；不能用固定零 invoke ID 欺骗关联。

## 5. 对象、属性和时间字段

对象标识由 object type 与 object instance 组成；属性标识可为规范枚举或明确的 proprietary（私有）范围。编码必须保留 context tag 的开闭、长度和 application tag（例如 unsigned、enumerated、character string、bit string、boolean、real/double、date/time）。数组属性的 index、`ALL`/不存在区分；ReadProperty/WriteProperty 的 object/property/index 不能被静默重排或省略。

运行期 object instance、property value、COV value、process identifier、invoke ID、transaction ID、时间窗口、UTC（协调世界时）日期时间与 daylight flag（夏令时标志）都只断言存在、类型、长度、同会话关联或跨会话 distinct。`I-Am` 的设备实例应和同一发现会话中被观察的设备状态关联，但不写死数值。COV lifetime、time synchronization、timestamp 和 validity 窗口不能用固定当前时间通过测试。

## 6. BACnet/TCP、IPv4/IPv6、多会话与 PCAP/NIC

BACnet/TCP 使用 TCP carrier（载体）与规范长度封帧：先按 TCP stream 重组，再按 BACnet/TCP 的 type/length 边界分离多个 BACnet NPDU/APDU；TCP segment、PSH 标志和 MSS 分段不是应用边界。TCP fixture 必须断言三次握手、双向方向、长度字段、粘连/分段重组和终止。BACnet/SC、TLS 或未知安全隧道没有实现时只能断言 TCP/TLS 外壳，不能声称解密后的 BACnet 字段。

IPv4 fixture 断言 `ip.proto=17`（UDP）或 `ip.proto=6`（TCP）；IPv6 fixture 断言最终 next header（下一报头）为 UDP/TCP 和独立地址族。至少两个并行会话/多流必须有独立四元组、invoke/transaction 映射、COV 状态和重组缓存；包可全局交织，但不得跨流配对响应。

PCAP（离线抓包）与 NIC（真实网卡捕获）必须使用同一 fixture；断言 Ethernet/IP/UDP 或 TCP carrier、BACnet 端口、BVLC/NPDU/APDU 层级、方向、动态 invoke/transaction 关联和服务字段一致。推荐 NIC 过滤器为 `udp port 47808 or tcp port 47808`，实际 TCP 端口若显式配置则使用该端口。checksum offload（校验和卸载）只影响校验和显示，不改变应用层断言。

## 7. 错误处理、负例和完成定义

6 个语义负例必须在 planner/validator 阶段失败并传播为 task error（任务错误），不能输出成功 PCAP、`completed/0 packet` 或只有 UDP/TCP 外壳的假成功。未来注册后的负例 `expect` 键集合严格为 `{"expect_error", "error_contains"}`；当前未注册 JSON 仅含占位。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `bacnet_neg_length_version_type` | BVLC/NPDU/APDU 长度越界、BVLC version/type/function 或 TCP length 错误 | `length`、`version` 或 `type` |
| `bacnet_neg_npdu_apdu` | NPDU 控制位与 DNET/SNET/Hop Count、网络层消息/APDU PDU type、confirmed/segmentation 字段不一致 | `npdu`、`apdu` 或 `segmentation` |
| `bacnet_neg_object_property` | 未知/越界 object type 或 instance、property/index/tag/value 类型错误 | `object`、`property` 或 `tag` |
| `bacnet_neg_carrier_port` | UDP/TCP 载体混用、错误端口、错误 BVLC/TCP profile 或非 BACnet/SC 边界被当明文 | `carrier`、`port`、`udp` 或 `tcp` |
| `bacnet_neg_address_family_bbmd` | IPv4/IPv6 地址族与层链冲突、广播/BBMD/foreign-device 字段和 function 不匹配 | `family`、`broadcast`、`bbmd` 或 `address` |
| `bacnet_neg_transaction_correlation` | invoke/transaction 不匹配、跨会话响应、段序/窗口错误、COV 订阅与通知错配 | `invoke`、`transaction`、`segment` 或 `match` |

合法的 BVLC 广播/转发、foreign-device TTL、confirmed/unconfirmed、Read/WriteProperty、COV、Error/Reject/Abort、分段、TCP 粘连、IPv4/IPv6、多会话和动态时间由正例覆盖，不能误报为负例。错误原因必须传播，不能用通用“0 packets”替代验证错误。

实现完成定义：注册 `bacnet` layer；实现 Ethernet→BVLC→NPDU→APDU 编码、UDP/BACnet/IP、广播/BBMD 边界、Who-Is/I-Am、Read/WriteProperty、COV、错误/拒绝/中止、confirmed segmentation、invoke/transaction correlation、BACnet/TCP framing、IPv4/IPv6、多会话、多流和 planner→worker→PCAP/NIC 正负完整传播；-race（竞态检测）与集成测试覆盖全部 20 个语义 ID。BACnet/SC/TLS 仍仅在明确实现后才可增加安全字段断言。

## 8. 20 个语义场景和 packet_count 映射

共 20 个唯一语义 ID：14 个正例和 6 个负例；顺序必须与 `65-bacnet-testcase.md` §2 及注册后的 `bacnet.json` 完全一致。当前 JSON 只有不计数的注册前置占位。

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `bacnet_bip_ipv4_unicast` | 正 | Ethernet/IPv4/UDP/BVLC 单播 NPDU/APDU | 8 |
| 2 | `bacnet_bip_ipv4_broadcast_bbmd` | 正 | UDP 广播、BVLC broadcast/forwarded、BBMD/foreign-device 边界 | 10 |
| 3 | `bacnet_bip6_ipv6` | 正 | BACnet/IPv6 地址族、UDP carrier 和 BVLC/NPDU | 8 |
| 4 | `bacnet_bvll_npdu_apdu_encoding` | 正 | BVLC version/function/length、NPDU 控制位、APDU PDU type | 8 |
| 5 | `bacnet_who_is_i_am` | 正 | Unconfirmed Who-Is/I-Am、动态设备实例和能力字段 | 8 |
| 6 | `bacnet_read_property` | 正 | Confirmed ReadProperty/complex-ack、object/property/index/value | 8 |
| 7 | `bacnet_write_property` | 正 | Confirmed WriteProperty/simple-ack、priority 和 application value | 8 |
| 8 | `bacnet_confirmed_segmentation` | 正 | confirmed service 分段、sequence/window、segment-ack 和 invoke 关联 | 14 |
| 9 | `bacnet_cov_subscription_notification` | 正 | SubscribeCOV、COVNotification、lifetime/value 动态关联 | 12 |
| 10 | `bacnet_error_reject_abort` | 正 | Error、Reject、Abort 结构、原因和失败 invoke 关联 | 12 |
| 11 | `bacnet_tcp_framing` | 正 | BACnet/TCP length framing、TCP 分段/粘连、明文 carrier 边界 | 12 |
| 12 | `bacnet_multi_session_stream` | 正 | 多会话/多流、状态隔离、transaction/invoke/COV 独立 | 24 |
| 13 | `bacnet_object_property_types` | 正 | 多 object/property、context/application tag、数组 index/value 类型 | 10 |
| 14 | `bacnet_pcap_nic_consistency` | 正 | PCAP/NIC、Ethernet/BVLC/NPDU/APDU、方向和动态关联一致 | 12 |
| 15 | `bacnet_neg_length_version_type` | 负 | BVLC/NPDU/APDU/TCP 长度和 version/type/function 错误 | — |
| 16 | `bacnet_neg_npdu_apdu` | 负 | NPDU 控制位、网络层消息、APDU/confirmed/segmentation 错误 | — |
| 17 | `bacnet_neg_object_property` | 负 | object/property/index/application tag/value 错误 | — |
| 18 | `bacnet_neg_carrier_port` | 负 | UDP/TCP carrier、BACnet 端口和 profile 边界错误 | — |
| 19 | `bacnet_neg_address_family_bbmd` | 负 | IPv4/IPv6、广播、BBMD/foreign-device 地址/function 错误 | — |
| 20 | `bacnet_neg_transaction_correlation` | 负 | transaction/invoke/segment/COV 跨流错配和错误传播 | — |

三方契约必须保持本文 §8、`65-bacnet-testcase.md` §2、注册后的 `bacnet.json` 同一组 20 个 ID、同一顺序、14 正例+6 负例；当前 JSON 另有一个不计数的 `bacnet_neg_unregistered`，且唯一预期为 `unknown layer`。

## 9. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 BACnet/ANSI-ASHRAE 135 正例和 6 个严格负例，覆盖 Ethernet、BVLC、NPDU、APDU、服务、分段、对象/属性、Who-Is/I-Am、Read/WriteProperty、COV、错误/拒绝/中止、UDP 广播/BBMD、BACnet/TCP、IPv4/IPv6、多会话/多流和 PCAP/NIC；不修改 Go/MCP 实现。
