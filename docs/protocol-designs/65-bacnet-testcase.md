# BACnet（楼宇自动化通信协议，Building Automation and Control Network）测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/65-bacnet-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/bacnet.json`  
> 状态：`bacnet` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§8 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `bacnet_neg_unregistered`，其 `expect` 必须 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

基线为 ANSI/ASHRAE 135；BACnet/IP 默认 UDP 47808。测试按 Ethernet→BVLC（BACnet 虚拟链路控制）→NPDU（网络协议数据单元）→APDU（应用协议数据单元）逐层验证。动态 `transaction_id`、`invoke_id`、object instance（对象实例）、COV value（值变化值）、时间和设备/进程标识不硬编码，使用 `presence`、`nonzero`、`same_as_packet`、`distinct`、类型和长度断言。没有真实 BBMD（BACnet 广播管理设备）或现场设备时，只断言 broadcast/foreign-device（外部设备）/forwarded-NPDU 的编码边界，不声称网络已转发。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `bacnet_bip_ipv4_unicast` | 正 | Ethernet/IPv4/UDP/BVLC 单播 NPDU/APDU | 8 |
| 2 | `bacnet_bip_ipv4_broadcast_bbmd` | 正 | UDP 广播、BVLC broadcast/forwarded、BBMD/foreign-device 边界 | 10 |
| 3 | `bacnet_bip6_ipv6` | 正 | BACnet/IPv6 地址族、UDP carrier 和 BVLC/NPDU | 8 |
| 4 | `bacnet_bvll_npdu_apdu_encoding` | 正 | BVLC version/function/length、NPDU 控制位、APDU PDU type | 8 |
| 5 | `bacnet_who_is_i_am` | 正 | Unconfirmed Who-Is/I-Am、动态设备实例和能力字段 | 8 |
| 6 | `bacnet_read_property` | 正 | Confirmed ReadProperty/complex-ack、object/property/index/value | 8 |
| 7 | `bacnet_write_property` | 正 | Confirmed WriteProperty/simple-ack、priority 和 application value | 8 |
| 8 | `bacnet_confirmed_segmentation` | 正 | confirmed service（确认服务）分段、sequence/window、segment-ack 和 invoke 关联 | 14 |
| 9 | `bacnet_cov_subscription_notification` | 正 | SubscribeCOV、COVNotification、lifetime/value 动态关联 | 12 |
| 10 | `bacnet_error_reject_abort` | 正 | Error、Reject、Abort 结构、原因和失败 invoke 关联 | 12 |
| 11 | `bacnet_tcp_framing` | 正 | BACnet/TCP length framing（长度封帧）、TCP 分段/粘连、明文 carrier 边界 | 12 |
| 12 | `bacnet_multi_session_stream` | 正 | 多会话/多流、状态隔离、transaction/invoke/COV 独立 | 24 |
| 13 | `bacnet_object_property_types` | 正 | 多 object/property、context/application tag、数组 index/value 类型 | 10 |
| 14 | `bacnet_pcap_nic_consistency` | 正 | PCAP/NIC、Ethernet/BVLC/NPDU/APDU、方向和动态关联一致 | 12 |
| 15 | `bacnet_neg_length_version_type` | 负 | BVLC/NPDU/APDU/TCP 长度和 version/type/function 错误 | — |
| 16 | `bacnet_neg_npdu_apdu` | 负 | NPDU 控制位、网络层消息、APDU/confirmed/segmentation 错误 | — |
| 17 | `bacnet_neg_object_property` | 负 | object/property/index/application tag/value 错误 | — |
| 18 | `bacnet_neg_carrier_port` | 负 | UDP/TCP carrier、BACnet 端口和 profile 边界错误 | — |
| 19 | `bacnet_neg_address_family_bbmd` | 负 | IPv4/IPv6、广播、BBMD/foreign-device 地址/function 错误 | — |
| 20 | `bacnet_neg_transaction_correlation` | 负 | transaction/invoke/segment/COV 跨流错配和错误传播 | — |

## 3. 正例逐项断言契约

1. **`bacnet_bip_ipv4_unicast`**：建立 Ethernet/IPv4/UDP 双向流，断言端口 47808、BVLC type `0x81`、function、长度覆盖 BVLC+NPDU、NPDU version 1、APDU 方向和动态事务字段。`packet_count=8`。
2. **`bacnet_bip_ipv4_broadcast_bbmd`**：断言 UDP 广播地址/MAC、original-broadcast 或 forwarded-NPDU、BVLC 原始地址/广播 function、Hop Count 和 BBMD/foreign-device 登记边界；不声称真实 BBMD 转发。`packet_count=10`。
3. **`bacnet_bip6_ipv6`**：独立 IPv6/UDP fixture，断言地址族、最终 UDP next header、显式 IPv6 BACnet carrier、BVLC/NPDU 外层和 47808；不得继承 IPv4 地址。`packet_count=8`。
4. **`bacnet_bvll_npdu_apdu_encoding`**：逐字段断言 Ethernet→IP→UDP→BVLC version/type/function/length→NPDU 控制位/DNET/SNET/Hop Count→APDU PDU type；每个父长度按编码字节计算。`packet_count=8`。
5. **`bacnet_who_is_i_am`**：断言未确认 Who-Is/I-Am 服务选择、设备实例范围、最大 APDU 长度、分段能力和 vendor identifier 的 application/context tag；设备实例与标识仅 presence/nonzero/type。`packet_count=8`。
6. **`bacnet_read_property`**：请求为 confirmed ReadProperty，断言动态 invoke ID、object identifier、property identifier、可选 array index；complex-ack 复用 invoke ID，响应 object/property 相同，value application tag 存在。`packet_count=8`。
7. **`bacnet_write_property`**：断言 confirmed WriteProperty 的 object/property/index/value、priority 和 simple-ack；动态 invoke ID `same_as_packet`，不声称现场持久化或真实写入成功。`packet_count=8`。
8. **`bacnet_confirmed_segmentation`**：将 confirmed service 分成多个 segment，断言 more-follows、sequence number、proposed window、segment-ack、最终 complex-ack 与 invoke ID 关联；按重组 APDU 验证字段，不把 UDP segment 当服务边界。`packet_count=14`。
9. **`bacnet_cov_subscription_notification`**：断言 SubscribeCOV 的 subscriber/process、object、issue-confirmed、动态 lifetime 与 simple-ack，再断言 COVNotification 的对象和值关联；时间/value 只 presence/type/same_as，不能硬编码。`packet_count=12`。
10. **`bacnet_error_reject_abort`**：分别观察 Error、Reject、Abort，断言错误 class/code、拒绝/中止原因、PDU 类型和失败 invoke 与请求 `same_as_packet`；不得以成功 ACK 替代失败路径。`packet_count=12`。
11. **`bacnet_tcp_framing`**：BACnet/TCP 明文 carrier 中拆分和粘连多个长度封帧，断言 TCP 握手、长度覆盖自身 payload、按 stream 重组后逐帧解析；TLS/BACnet/SC 仅断言不透明外壳。`packet_count=12`。
12. **`bacnet_multi_session_stream`**：至少两个 UDP/TCP 会话或多流并行，断言每流独立四元组、transaction/invoke、COV 订阅、重组缓存和响应；允许全局交织，不跨流配对。`packet_count=24`。
13. **`bacnet_object_property_types`**：覆盖至少两种 object/property、数组 index、unsigned/enumerated/character string/boolean/real/date-time 等 application/context tag 的类型和长度；实例和值动态，不能只断言字段存在。`packet_count=10`。
14. **`bacnet_pcap_nic_consistency`**：同一明文 BACnet/IP fixture 分别输出 PCAP 并执行 NIC 捕获，断言 Ethernet/IP/UDP、47808、BVLC/NPDU/APDU 层级、方向、服务和动态 invoke/transaction 关联一致；推荐过滤器 `udp port 47808 or tcp port 47808`，记录 checksum offload 差异。`packet_count=12`。

没有真实设备/BBMD/时间同步/SC 密钥时，不添加“设备在线”“属性已持久化”“BBMD 已跨网转发”“时间有效”“签名/加密成功”等断言。没有专用 BACnet dissector（解析器）时，使用稳定 Ethernet/IP/UDP/TCP 字段、raw payload（原始载荷）和逐层长度/tag 断言；不自创字段名。

## 4. 负例契约

每个负例必须在 planner/validator 失败并传播为 task error（任务错误）；不能产生成功 PCAP、`completed/0 packet` 或只有 UDP/TCP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`，因此 packet_count 为 `—`，不添加 `notes`、`min_packets` 或其他键。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `bacnet_neg_length_version_type` | BVLC/NPDU/APDU/TCP length 越界，BVLC version/type/function 错误 | `length`、`version` 或 `type` |
| `bacnet_neg_npdu_apdu` | NPDU 控制位、DNET/SNET/Hop Count、网络层消息/APDU/confirmed/segmentation 不一致 | `npdu`、`apdu` 或 `segmentation` |
| `bacnet_neg_object_property` | object type/instance、property/index、application tag 或 value 类型错误 | `object`、`property` 或 `tag` |
| `bacnet_neg_carrier_port` | UDP/TCP 混用、错误 BACnet 端口、错误 BVLC/TCP profile 或将安全 carrier 当明文 | `carrier`、`port`、`udp` 或 `tcp` |
| `bacnet_neg_address_family_bbmd` | IPv4/IPv6 与层链冲突、广播/BBMD/foreign-device function 或地址错误 | `family`、`broadcast`、`bbmd` 或 `address` |
| `bacnet_neg_transaction_correlation` | invoke/transaction 不匹配、跨流响应、段序/窗口错误、COV 订阅通知错配 | `invoke`、`transaction`、`segment` 或 `match` |

负例不应污染正例 fixture；每个输入单独执行，错误必须保留原始原因，不能静默补全动态字段或以 0 包成功。

## 5. 三方一致性和静态检查

1. 设计 `65-bacnet-design.md` §8、本文 §2、注册后的 `bacnet.json` 和审计必须保持同一组 20 个 ID、同一顺序、14 正例+6 负例；当前 JSON 只含 `bacnet_neg_unregistered` 占位。
2. 未来 14 个正例均应有 `packet_count`/`min_packets`、carrier、方向、BVLC/NPDU/APDU 稳定字段和动态关联；6 个负例的 `expect` 键集合恰为 `{expect_error,error_contains}`，且 packet_count 为 `—`。
3. BVLC length 覆盖 BVLC+NPDU，NPDU 控制位决定地址/消息字段，APDU PDU type 与服务/confirmed/segmentation 一致；不能把 UDP/TCP 分段当应用边界。
4. Who-Is/I-Am、ReadProperty、WriteProperty、SubscribeCOV/COVNotification、Error/Reject/Abort 均按服务选择、context/application tag、方向和 invoke/transaction 关联断言；不硬编码实例、值或时间。
5. confirmed 分段按 more-follows/sequence/window/segment-ack 重组；响应 invoke ID 同会话匹配，跨会话/跨流错配进入负例。
6. IPv4/IPv6、UDP 47808、BACnet/TCP 长度封帧、广播/BBMD/foreign-device 和 PCAP/NIC 观察各有正例；BACnet/SC/TLS 未实现时只能断言 carrier 边界。
7. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/bacnet.json` 应成功；当前数组只能有 `bacnet_neg_unregistered`，且 `proto=bacnet`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。

## 6. 实现后执行建议

注册 `bacnet` layer 后，先检查 JSON parser（解析器）、层链自动补 IP、BVLC/NPDU/APDU 长度和动态关联，再运行 1–14 的 PCAP/NIC 正例与 15–20 的错误传播。若环境没有 BACnet dissector，使用通用 Ethernet/IP/UDP/TCP 字段和 raw payload/tag 边界；不能将唯一 placeholder 的拒绝结果报告为 BACnet suite 通过。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 BACnet 正例和 6 个严格负例，覆盖 Ethernet、BVLC、NPDU、APDU、服务、分段、对象/属性、Who-Is/I-Am、Read/WriteProperty、COV、Error/Reject/Abort、UDP 广播/BBMD、BACnet/TCP、IPv4/IPv6、多会话/多流和 PCAP/NIC；不修改 Go/MCP 实现。
