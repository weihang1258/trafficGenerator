# MMSE（多媒体消息服务封装，Multimedia Messaging Service Encapsulation）设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-21  
> 状态：仅设计与 PCAP（抓包文件）/NIC（网卡）用例契约；`mmse` 层尚未注册，不修改 Go（编程语言）/MCP（模型上下文协议）实现，不宣称当前测试套件可运行。  
> 配套文件：`docs/protocol-designs/71-mmse-testcase.md`、`trafficgen/test/protocol_pcap/cases/mmse.json`  
> 规范基线：OMA-TS-MMS_ENC（MMS Encapsulation，彩信封装）、OMA-TS-WAPProv（WAP，移动无线应用协议）、WAP-230-WSP（无线会话协议，Wireless Session Protocol）、WAP-230-WTP（无线事务协议，Wireless Transaction Protocol）、RFC 2616/7230（HTTP，超文本传输协议）、RFC 2045/2046（MIME，多用途互联网邮件扩展）。

## 1. 范围、证据等级和未注册边界

本契约覆盖 MMS（多媒体消息服务，Multimedia Messaging Service）消息在 WAP/WSP/WTP 与 HTTP 载体上的封装边界。应用层覆盖 `M-Send.req`、`M-Send.conf`、`M-Send.ind`、`M-Notification.ind`、`M-Retrieve.conf`、`M-Delivery.ind`、`M-Acknowledge.ind`；消息体覆盖 MMS 头、`Content-Type`、`Content-Length`、multipart（多部分 MIME）、SMIL（同步多媒体集成语言，Synchronized Multimedia Integration Language）以及文本、图片、音频附件。

WSP/WTP 是二进制会话/事务载体，HTTP 是另一种明确的承载 profile（档案）；两者的 method、header code、长度编码、事务确认和端口规则不能混用。WTP transaction（事务）与 MMS message/transaction ID（消息/事务标识）是不同命名空间：所有 ID、时间、multipart boundary（多部分边界）和动态附件元数据均由运行期生成，断言只能使用 `presence`、`nonzero`、`distinct`、`same_as_packet`、类型/长度和流内关联。

当前仓库没有注册 `mmse` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/mmse.json` 只能保留一个不计入语义覆盖的 `mmse_neg_unregistered` 注册前置占位，且 `expect_error=true`、`error_contains` 精确为 `unknown layer`；注册前拒绝、0 包或空 PCAP 不是 MMS 行为通过。

## 2. 推荐层链、配置和载体 profile

实现后的推荐层链为：

- WAP/WSP/WTP/IPv4：`[ip, udp, wtp, wsp, mmse]`；
- WAP/WSP/WTP/IPv6：`[ipv6, udp, wtp, wsp, mmse]`；
- HTTP/IPv4：`[ip, tcp, http, mmse]`；
- HTTP/IPv6：`[ipv6, tcp, http, mmse]`。

层链仅为未来接入契约，不表示当前注册。示例配置：

```json
{
  "protocol": "mmse",
  "config": {
    "layers": [{"udp": {}}, {"wtp": {}}, {"wsp": {}}, {"mmse": {}}],
    "src_ip": "192.0.2.71",
    "dst_ip": "198.51.100.71",
    "mmse": {
      "carrier": "wap",
      "message_flow": "send",
      "transactions": [{"type": "M-Send.req", "response": "M-Send.conf"}],
      "content": {"type": "multipart-related", "smil": true, "parts": ["text", "image", "audio"]}
    }
  }
}
```

| 配置项 | 约束 |
|---|---|
| `carrier` | `wap` 走 WSP/WTP 二进制边界；`http` 走 HTTP request/response。载体声明必须与真实 payload 一致。 |
| `transport`/端口 | WAP/WSP/WTP 通常使用 UDP 9201（连接模式可按 fixture 选择 9200/9201）；HTTP 使用 TCP 80，HTTPS 443 未解密时只能断言 TCP/TLS。端口必须随 profile 生效，不得以另一载体代替。 |
| `message_type` | 只能使用已定义 MMS 消息类型；请求、指示、确认、通知和投递确认的方向/响应关系须显式可关联。 |
| `transaction_id`/`message_id` | 分别表示 WTP/MMS 事务和消息关联。运行期生成且同一会话内保持关联，不把一个 ID 命名空间当成另一个。 |
| `content_type` | `application/vnd.wap.mms-message` 为 MMS 外层；multipart 使用合法 MIME 类型和动态 boundary；SMIL 根部件与附件引用必须一致。 |
| `content_length` | 等于实际编码后的 body bytes（字节），WSP 长度值按 WSP length-code 规则编码；不得以字符数、Base64（基64编码）长度或附件逻辑长度替代。 |
| `parts` | text、image、audio 至少保留 MIME 类型、Content-ID/Location、长度和内容边界；动态内容只断言存在、非零和引用关联。 |
| `wire_fault` | 仅负例注入口：`wsp-header`、`wsp-length`、`message-transaction`、`multipart-boundary`、`carrier-port-family`、`propagation`。 |

## 3. WSP/WTP 与 HTTP 封装边界

WSP header（头部）是二进制编码，必须按 field code、value-length、短整数/长整数和 opaque（不透明字节串）规则逐字段解析。WSP header 的长度覆盖实际 header 内容，不可把 HTTP 的冒号文本头直接塞入 WSP。WTP transaction 的 Invoke/Result/ACK（确认）方向、事务边界和重传语义独立于 MMS message type；分段或重组后仍须按 WTP/WSP 边界解析。

HTTP profile 使用明确的 request method、URI、`Content-Type`、`Content-Length` 或 chunked（分块传输）规则。HTTP body 是 MMS 编码字节；HTTP 200 不等于 MMS 业务确认成功，必须观察 `M-Send.conf` 或对应消息类型。HTTP keep-alive（长连接）上的多个事务按 Content-Length/chunked 分隔，不能跨请求复用 MMS transaction/message ID。

WAP carrier 与 HTTP carrier 应使用独立 fixture，分别断言 UDP/WTP/WSP 或 TCP/HTTP 的下一层、端口、地址族和消息边界。WTP/WSP 的 binary payload 与 HTTP 的 textual header framing（文本头部封装）不能互换；IPv4/IPv6 必须由真实 IP 层承载，不能只替换地址字符串。

## 4. MMS 消息语义和动态关联

- **`M-Send.req`/`M-Send.conf`**：发送方请求携带动态 message ID、发件人/收件人和内容体；确认必须在同一事务关联，状态字段不能被静默改为成功。
- **`M-Send.ind`**：服务端向接收侧指示已收到或转发的消息；其消息关联应与相应发送事务可追踪，但不复用另一会话的 transaction ID。
- **`M-Notification.ind`**：通知待取消息，携带动态 content location、消息大小和过期/时间字段；时间只验证格式、顺序和存在性，不硬编码时刻。
- **`M-Retrieve.conf`**：取回完整消息，必须能与通知的动态 location/message ID 关联，且 multipart body 的边界、根部件和附件引用完整。
- **`M-Delivery.ind`**：投递状态指示，状态码、收件消息 ID 和时间字段与消息关联；不宣称真实终端已展示内容。
- **`M-Acknowledge.ind`**：确认收到通知或投递结果；方向、消息类型和关联 ID 必须正确，不以 TCP ACK/WTP ACK 代替 MMS 业务确认。

消息头中的日期、过期时间、大小和 ID 是动态值。多会话/多流必须为每个流维护独立的 WTP/WSP/MMS 状态、重组缓存、消息关联和附件边界；全局交织不能造成跨流匹配。

## 5. multipart MIME、SMIL 与附件

multipart body 的父 Content-Type 必须包含动态 boundary 参数；父 `Content-Length` 覆盖全部编码后的 multipart bytes，每个 part 的头部和 CRLF（回车换行）边界均计入长度。boundary 不能出现在 part payload 中，结束边界必须完整；boundary 参数的引用/转义按 MIME 编码规则处理。

SMIL 是根部件或声明的演示描述，必须使用合法 MIME 类型，并通过动态 `Content-ID`/`Content-Location` 引用文本、图片和音频 part。文本、图片、音频附件分别断言 MIME 类型、编码边界、长度和引用存在；没有真实媒体播放器或终端时，不宣称渲染成功、播放成功或内容语义正确。二进制附件只断言 magic bytes（魔数）/长度/part 边界等稳定证据，不硬编码完整媒体内容。

若使用 base64 或 quoted-printable（可打印字符编码），`Content-Transfer-Encoding` 必须与实际 body 一致，解码后的长度与 part 声明一致；MMS/WSP 的长度字段仍以线上编码 bytes 为准。

## 6. IPv4/IPv6、多会话、多流与 PCAP/NIC

IPv4 和 IPv6 使用独立 fixture，分别断言 IP 版本、UDP/WTP/WSP 或 TCP/HTTP carrier、端口、方向和校验和可观察边界。一个会话可包含多个 MMS 事务；多个会话必须使用独立四元组或明确的流标识，transaction ID、message ID、通知 location、时间和 multipart boundary 不跨会话共享。

正例应分别支持 PCAP 文件输出和 NIC 捕获：比较 Ethernet/IP、WAP 或 HTTP carrier、方向、端口、MMS message type、WSP/HTTP headers、Content-Length、multipart/SMIL/附件边界和动态关联。没有专用 MMSE dissector（解析器）时，使用 UDP/TCP/IP/HTTP 字段、raw payload（原始载荷）和脚本重组；不自创未注册的 tshark（抓包解析器）字段。NIC 断言记录 checksum offload（校验和卸载）可能造成的显示差异。

## 7. 负例、错误传播和完成定义

6 个语义负例必须在 planner/validator 阶段失败并传播为 task error（任务错误），不能生成成功 PCAP、`completed/0 packet` 或只有 UDP/TCP/HTTP 外壳的假成功。未来注册后的负例 `expect` 键集合严格为 `{"expect_error","error_contains"}`，packet_count 写 `—`，不添加 `notes`、`min_packets` 或字段断言。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `mmse_neg_wsp_header` | WSP field code、value-length、短/长整数或 opaque header 编码非法 | `wsp` 或 `header` |
| `mmse_neg_wsp_length` | WSP/WTP/MMS 父长度越界、分段截断或 Content-Length 与实际 bytes 不一致 | `length` 或 `truncation` |
| `mmse_neg_message_transaction` | MMS message type、WTP transaction、message ID 或 response 方向错配 | `transaction`、`message` 或 `match` |
| `mmse_neg_multipart_boundary_encoding` | multipart boundary 缺失/冲突、part 截断、SMIL 引用不存在或传输编码不符 | `boundary`、`multipart` 或 `encoding` |
| `mmse_neg_http_wap_carrier` | WSP 字节用于 HTTP、HTTP 头用于 WAP、端口/IPv4/IPv6/UDP/TCP profile 冲突 | `carrier`、`http`、`wap`、`port` 或 `family` |
| `mmse_neg_error_propagation` | planner/validator 已知非法消息却被吞掉，任务错误未向 worker/output 传播 | `error`、`validation` 或 `propagat` |

错误必须保留最具体原因并从 planner 传到 task；不能自动补齐错误的 WSP 长度、重排 message type、跨会话配对响应、生成空 body 后标记完成或用 0 包掩盖失败。

实现完成定义：注册 `mmse` layer；实现 WSP/WTP/HTTP carrier、MMS 消息头与六类消息语义、multipart/SMIL/附件、Content-Length/编码、IPv4/IPv6、多会话/多流和 PCAP/NIC；planner→worker→输出完整传播；20 个语义场景的正负集成测试与 `-race`（竞态检测）通过。

## 8. 20 个语义场景和 packet_count 映射

共 20 个唯一语义 ID：14 个正例和 6 个负例；顺序必须与 `71-mmse-testcase.md` §2 及未来注册后的 `mmse.json` 完全一致。当前 JSON 只有不计数的注册前置占位。

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

三方契约必须保持本文 §8、`71-mmse-testcase.md` §2、注册后的 `mmse.json` 同一组 20 个 ID、同一顺序、14 正例+6 负例；当前 JSON 另有一个不计数的 `mmse_neg_unregistered`，且唯一预期为 `unknown layer`。

## 9. 修订记录

- v1.0.0（2026-08-21）：建立 14 个 MMSE 正例和 6 个严格负例，覆盖 OMA/WAP WSP/WTP/HTTP carrier、MMS 六类消息、multipart MIME、SMIL、文本/图片/音频附件、Content-Type/Content-Length、IPv4/IPv6、多会话/多流、PCAP/NIC 和错误传播；不修改 Go/MCP 实现。
