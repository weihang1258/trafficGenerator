# MMSE（多媒体消息服务封装，Multimedia Messaging Service Encapsulation）测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-21  
> 配套设计：`docs/protocol-designs/71-mmse-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/mmse.json`  
> 状态：`mmse` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前测试套件可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§8 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `mmse_neg_unregistered`，其 `expect` 必须 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

测试同时验证应用消息和 carrier（载体）边界。WAP/WSP/WTP 为二进制载体，HTTP 为独立 TCP 载体；不能用 HTTP 文本头替代 WSP header（头部），也不能将 TCP ACK/WTP ACK 当作 MMS 业务确认。动态 transaction/message ID、时间、multipart boundary（多部分边界）、附件内容和地址不硬编码，使用 `presence`、`nonzero`、`distinct`、`same_as_packet`、长度/类型及同一流关联。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `mmse_wap_wsp_ipv4_send` | 正 | WAP/WSP/WTP、IPv4、M-Send.req/resp 边界 | 10 |
| 2 | `mmse_http_ipv4_send_retrieve` | 正 | HTTP/IPv4、M-Send 与 M-Retrieve 请求响应 | 12 |
| 3 | `mmse_wtp_wsp_ipv6_notification` | 正 | WTP/WSP、IPv6、M-Notification.ind | 10 |
| 4 | `mmse_m_send_req_ind` | 正 | M-Send.req、M-Send.conf、M-Send.ind 动态关联 | 12 |
| 5 | `mmse_m_notification_ind` | 正 | Notification.ind、location、大小和时间结构 | 8 |
| 6 | `mmse_m_retrieve_conf` | 正 | Retrieve.conf、通知关联与完整 multipart body | 12 |
| 7 | `mmse_m_delivery_ind_ack` | 正 | Delivery.ind、Acknowledge.ind、状态和方向 | 10 |
| 8 | `mmse_multipart_mime_smil` | 正 | multipart MIME、动态 boundary、SMIL 根部件 | 12 |
| 9 | `mmse_text_image_audio_attachments` | 正 | 文本、图片、音频 MIME part、引用和长度 | 12 |
| 10 | `mmse_content_type_length` | 正 | MMS/WSP/HTTP Content-Type、Content-Length 编码 | 10 |
| 11 | `mmse_ipv4_ipv6_sessions` | 正 | IPv4/IPv6 独立会话和 carrier 边界 | 16 |
| 12 | `mmse_multi_session_multi_flow` | 正 | 多会话、多流、交织和状态隔离 | 24 |
| 13 | `mmse_http_wap_carrier_equivalence` | 正 | HTTP/WAP 两种 carrier 的等价 MMS 语义 | 16 |
| 14 | `mmse_pcap_nic_consistency` | 正 | PCAP/NIC、方向、端口和 payload 边界一致 | 14 |
| 15 | `mmse_neg_wsp_header` | 负 | WSP header code/length/opaque 编码错误 | — |
| 16 | `mmse_neg_wsp_length` | 负 | WSP/WTP/MMS 长度越界或截断 | — |
| 17 | `mmse_neg_message_transaction` | 负 | 消息类型、事务、ID 和响应方向错配 | — |
| 18 | `mmse_neg_multipart_boundary_encoding` | 负 | multipart boundary、SMIL 引用和传输编码错误 | — |
| 19 | `mmse_neg_http_wap_carrier` | 负 | HTTP/WAP carrier、端口、传输协议或地址族错误 | — |
| 20 | `mmse_neg_error_propagation` | 负 | planner/validator 错误传播，不得伪成功 | — |

## 3. 正例逐项断言契约

1. **`mmse_wap_wsp_ipv4_send`**：IPv4/UDP WTP/WSP 双向流，观察 WAP 端口、WTP transaction、WSP binary headers、M-Send.req 与 M-Send.conf，动态消息 ID 在同一流关联，`packet_count=10`。
2. **`mmse_http_ipv4_send_retrieve`**：IPv4/TCP/HTTP request/response，断言 MMS Content-Type、Content-Length、M-Send.req/conf 和 M-Retrieve.conf 的 body 边界；HTTP 200 不替代 MMS 业务状态，`packet_count=12`。
3. **`mmse_wtp_wsp_ipv6_notification`**：IPv6/UDP WTP/WSP，断言 IPv6 地址族、WAP carrier、M-Notification.ind、动态 content location/大小/时间字段，`packet_count=10`。
4. **`mmse_m_send_req_ind`**：覆盖 M-Send.req、M-Send.conf 和服务侧 M-Send.ind；断言请求/确认/指示方向、message ID 关联和 WTP 事务独立性，`packet_count=12`。
5. **`mmse_m_notification_ind`**：断言 Notification.ind 的消息类型、动态 location、大小、过期/时间字段和确认方向；时间只校验格式及相对边界，`packet_count=8`。
6. **`mmse_m_retrieve_conf`**：通知后的 Retrieve 请求/确认必须带完整 MMS body；断言 location/message ID 关联、multipart 父长度、结束边界和附件引用，`packet_count=12`。
7. **`mmse_m_delivery_ind_ack`**：断言 Delivery.ind 状态、消息 ID、时间和 Acknowledge.ind 方向/关联；不能用 TCP/WTP ACK 代替 MMS 确认，`packet_count=10`。
8. **`mmse_multipart_mime_smil`**：断言 multipart MIME 父 Content-Type 与动态 boundary、根部件 SMIL 类型、每个 part 的头/CRLF/长度和结束边界；SMIL 引用必须指向存在的 part，`packet_count=12`。
9. **`mmse_text_image_audio_attachments`**：分别观察 text/plain、图片和音频 part 的 MIME、Content-ID/Location、长度、magic bytes 和引用关联；不声称终端渲染或播放，`packet_count=12`。
10. **`mmse_content_type_length`**：分别在 WSP 与 HTTP 载体观察 MMS Content-Type；校验 WSP length-code、HTTP Content-Length/chunked 与实际编码 body bytes 一致，不以字符或 Base64 长度替代，`packet_count=10`。
11. **`mmse_ipv4_ipv6_sessions`**：独立 IPv4/IPv6 fixture，断言相应 IP 版本、UDP/WTP/WSP 或 TCP/HTTP carrier、端口、方向和状态隔离，`packet_count=16`。
12. **`mmse_multi_session_multi_flow`**：至少两个会话、多个流并行并交织；断言每流 WTP/WSP/MMS 状态、动态 ID、通知 location、multipart boundary 和附件引用不跨流混用，`packet_count=24`。
13. **`mmse_http_wap_carrier_equivalence`**：同一业务消息分别经 HTTP 和 WAP carrier 发送/取回；断言应用消息语义一致，但 WSP binary framing、HTTP framing、端口和传输层各自正确，`packet_count=16`。
14. **`mmse_pcap_nic_consistency`**：同一 fixture 输出 PCAP 并进行 NIC 捕获；比较 IP 族、载体、方向、端口、MMS 类型、WSP/HTTP headers、Content-Length、multipart/SMIL/附件边界和动态关联，`packet_count=14`。

无专用 MMSE dissector（解析器）时，使用 `ip`/`ipv6`、`udp`/`tcp`、`http`、raw payload 和脚本重组；不得自创 tshark（抓包解析器）字段。没有终端或媒体播放器证据时，不添加“彩信已展示”“音频已播放”“投递成功”等断言。

## 4. 负例契约

每个负例必须在 planner/validator 阶段失败并传播为 task error（任务错误）；不能产生成功 PCAP、`completed/0 packet` 或只有 UDP/TCP/HTTP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`，因此 packet_count 为 `—`，不添加 `notes`、`min_packets` 或其他键。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `mmse_neg_wsp_header` | WSP field code、value-length、短/长整数或 opaque header 编码非法 | `wsp` 或 `header` |
| `mmse_neg_wsp_length` | WSP/WTP/MMS 父长度越界、分段截断或 Content-Length 与实际 bytes 不一致 | `length` 或 `truncation` |
| `mmse_neg_message_transaction` | MMS message type、WTP transaction、message ID 或 response 方向错配 | `transaction`、`message` 或 `match` |
| `mmse_neg_multipart_boundary_encoding` | multipart boundary 缺失/冲突、part 截断、SMIL 引用不存在或传输编码不符 | `boundary`、`multipart` 或 `encoding` |
| `mmse_neg_http_wap_carrier` | WSP 字节用于 HTTP、HTTP 头用于 WAP、端口/IPv4/IPv6/UDP/TCP profile 冲突 | `carrier`、`http`、`wap`、`port` 或 `family` |
| `mmse_neg_error_propagation` | planner/validator 已知非法消息却被吞掉，任务错误未向 worker/output 传播 | `error`、`validation` 或 `propagat` |

合法的动态 ID、时间、boundary、multipart parts、WSP 长度和 HTTP framing 由正例覆盖；不能将运行期动态值写入固定断言。错误传播必须保留原始原因，不能用通用“0 packets”替代验证错误。

## 5. 三方一致性和静态检查

1. 设计 `71-mmse-design.md` §8、本文 §2、注册后的 `mmse.json` 和审计必须保持同一组 20 个 ID、同一顺序：14 正例 + 6 负例；当前 JSON 另有 `mmse_neg_unregistered` 占位。
2. 未来 14 个正例均有 `packet_count`/`min_packets`、carrier、方向、MMS 类型、动态关联和稳定长度/边界字段；6 个负例的 `expect` 键集合恰为 `{expect_error,error_contains}`，packet_count 为 `—`。
3. WSP/WTP 二进制长度和事务边界、HTTP method/header/body framing、M-Send/M-Notification/M-Retrieve/M-Delivery/M-Acknowledge 消息语义必须分别有对应正例或明确关联断言。
4. multipart 父/part 长度按编码 bytes 计算，动态 boundary 完整且不冲突；SMIL 根部件引用实际存在的 text/image/audio part；传输编码和 MIME 类型一致。
5. 动态 transaction/message ID、时间、location、boundary 和附件值只用 presence/nonzero/distinct/same_as_packet/类型长度，不枚举固定运行期值。
6. WAP/WSP/WTP 与 HTTP carrier、UDP/TCP 端口、IPv4/IPv6、多会话/多流、PCAP/NIC 各有正例；负例必须覆盖 WSP header/length、消息事务、multipart/编码、carrier/端口/地址族和错误传播。
7. 负例 `expect` 只有 `expect_error` 和 `error_contains`；不得以正例透明观察、空 PCAP 或 0 包完成掩盖验证失败。
8. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/mmse.json` 应成功；当前数组只能含 `mmse_neg_unregistered`，且 `proto=mmse`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。

## 6. 实现后执行建议

注册 `mmse` layer 后，先检查 JSON parser、ID 顺序、WSP/WTP 与 HTTP framing、MMS message type/transaction 关联、multipart offsets/length、SMIL 引用、动态字段断言和负例错误传播，再运行 1–14 的 PCAP/NIC 正例与 15–20 的负例。当前占位只证明层未注册，不得报告为 MMSE 测试套件通过。

## 7. 修订记录

- v1.0.0（2026-08-21）：建立 14 个 MMSE 正例和 6 个严格负例，覆盖 OMA/WAP WSP/WTP/HTTP carrier、MMS 消息类型、multipart MIME、SMIL、文本/图片/音频附件、Content-Type/Content-Length、IPv4/IPv6、多会话/多流、PCAP/NIC 和错误传播；不修改 Go/MCP 实现。
