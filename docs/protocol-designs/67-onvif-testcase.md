# ONVIF（网络视频接口论坛，Open Network Video Interface Forum）测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/67-onvif-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/onvif.json`  
> 状态：`onvif` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§8 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `onvif_neg_unregistered`，其 `expect` 必须 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

ONVIF carrier（载体）为 HTTP（超文本传输协议，Hypertext Transfer Protocol）POST、明确声明的资源 GET 或 HTTPS/TLS 外壳；推荐层链为 `[tcp, http, onvif]`，地址 `192.0.2.67`/`198.51.100.67`，端口 80。WS-Discovery Probe 的实际发现传输应在 fixture 中明确声明 UDP/3702 或专用发现封装，不能把普通 HTTP/80 假定为发现协议。没有设备、事件源、TLS 解密密钥或签名验证上下文时，只断言 TCP/HTTP、SOAP 1.2、XML namespace、服务操作、动态关联和不透明安全字段；不能声称能力真实、流 URI 可播放、认证/签名有效或事件已由设备接受。MessageID、UUID、token、timestamps、nonce 和 signature 均不得硬编码。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `onvif_discovery_probe_ipv4` | 正 | WS-Discovery Probe/ProbeMatch、IPv4、动态 MessageID/RelatesTo | 8 |
| 2 | `onvif_device_get_capabilities` | 正 | Device GetCapabilities、SOAP 1.2、能力 namespace/地址 | 8 |
| 3 | `onvif_media_get_profiles` | 正 | Media GetProfiles、profile token 和配置结构 | 8 |
| 4 | `onvif_media_get_stream_uri` | 正 | GetStreamUri、profile token/URI 关联、HTTP carrier | 8 |
| 5 | `onvif_events_pullpoint` | 正 | CreatePullPointSubscription/PullMessages、通知和订阅状态 | 12 |
| 6 | `onvif_core_soap_headers` | 正 | SOAP 1.2 envelope、XML namespace、HTTP POST/header | 8 |
| 7 | `onvif_ws_addressing` | 正 | Action/MessageID/To/RelatesTo 动态关联 | 8 |
| 8 | `onvif_ws_security_opaque` | 正 | UsernameToken/Timestamp/Signature opaque 边界 | 8 |
| 9 | `onvif_http_get_post` | 正 | HTTP POST SOAP 与明确资源 GET、method/content type | 10 |
| 10 | `onvif_ipv6_transport` | 正 | IPv6/TCP/80、SOAP carrier 和独立地址族 | 8 |
| 11 | `onvif_multi_session_streams` | 正 | 多会话/多流、profile、订阅和 MessageID 隔离 | 16 |
| 12 | `onvif_multi_media_event_flow` | 正 | Media 与 Events 并行、多服务响应关联 | 16 |
| 13 | `onvif_tls_opaque_carrier` | 正 | HTTPS/TLS 未解密时仅断言 carrier/端口/方向 | 8 |
| 14 | `onvif_pcap_nic_consistency` | 正 | PCAP/NIC、HTTP/TCP、SOAP 稳定字段和方向一致 | 12 |
| 15 | `onvif_neg_xml_soap_namespace` | 负 | XML/SOAP envelope、服务 namespace 错误 | — |
| 16 | `onvif_neg_soap_action_content_type` | 负 | SOAPAction/action、HTTP method/content type 错误 | — |
| 17 | `onvif_neg_addressing_body` | 负 | WS-Addressing 与 SOAP body/响应关联错误 | — |
| 18 | `onvif_neg_operation_parameter` | 负 | 操作参数、profile/token、事件状态错误 | — |
| 19 | `onvif_neg_carrier_port_family` | 负 | 载体、TCP 端口、IPv4/IPv6 和 TLS 边界错误 | — |
| 20 | `onvif_neg_correlation_error_propagation` | 负 | 多流关联、错误传播、订阅 token/RelatesTo 错误 | — |

## 3. 正例逐项断言契约

1. **`onvif_discovery_probe_ipv4`**：建立 IPv4 fixture（固定样本），按实现明确声明 discovery carrier（发现载体；推荐 UDP/3702），断言 Probe 的 discovery namespace、Types/Scopes、动态 MessageID，ProbeMatch（探测匹配）的 endpoint address（端点地址）和 `RelatesTo` 与请求关联；不硬编码 UUID，`packet_count=8`。
2. **`onvif_device_get_capabilities`**：HTTP POST/80 携带 SOAP 1.2，断言 Device namespace、GetCapabilities 操作、响应中的 Device/Media/Events capability 地址结构；地址只做 URI 存在和格式断言，`packet_count=8`。
3. **`onvif_media_get_profiles`**：断言 Media GetProfiles 请求/响应、至少一个动态 profile token、Video/Audio/ PTZ（云台）配置元素的 namespace 与层级；不声称设备真实配置，`packet_count=8`。
4. **`onvif_media_get_stream_uri`**：请求包含与 GetProfiles 关联的 profile token，响应包含同 token 上下文的媒体 URI 和传输配置；只断言 URI 存在/格式，不声称 RTP 可播放，`packet_count=8`。
5. **`onvif_events_pullpoint`**：先断言 CreatePullPointSubscription 的 Events namespace、订阅 reference、动态 token/termination time，再断言 PullMessages 携带同订阅上下文并返回通知；时间和 UUID 使用 presence/same_as，`packet_count=12`。
6. **`onvif_core_soap_headers`**：断言 SOAP 1.2 envelope URI、Header/Body 顺序、ONVIF service namespace、HTTP POST 和 `application/soap+xml`；prefix（前缀）可变而 namespace URI 不可变，`packet_count=8`。
7. **`onvif_ws_addressing`**：断言 Action、To、MessageID、响应 RelatesTo 的 XML namespace 和方向；响应 `RelatesTo same_as_packet` 请求 MessageID，不同会话 MessageID `distinct`，`packet_count=8`。
8. **`onvif_ws_security_opaque`**：断言 WS-Security namespace、UsernameToken/Nonce/Created 或 Timestamp、可选 BinarySecurityToken/Signature 的结构、算法 URI 和不透明长度；无密钥不声称认证或签名成功，`packet_count=8`。
9. **`onvif_http_get_post`**：一条 SOAP POST 与一条明确声明的资源/媒体 GET，断言 HTTP method、Host、URI、content type、状态和方向；不得把 GET 静默解析为 SOAP POST，`packet_count=10`。
10. **`onvif_ipv6_transport`**：独立 IPv6/TCP/80 fixture，断言地址族、最终 TCP next header、HTTP/SOAP carrier 和方向；IPv6 地址不从 IPv4 样本继承，`packet_count=8`。
11. **`onvif_multi_session_streams`**：至少两个并行 HTTP keep-alive 会话/流，断言每流独立 MessageID、RelatesTo、profile token、重组缓存和响应；允许全局交织，不跨流匹配，`packet_count=16`。
12. **`onvif_multi_media_event_flow`**：Media GetProfiles/GetStreamUri 与 Events PullPoint 并行，断言服务 namespace、操作、响应和 session/subscription 关联，动态 token/时间只做类型和 same-as，`packet_count=16`。
13. **`onvif_tls_opaque_carrier`**：HTTPS/TCP/443 未解密时只断言 TCP 握手、TLS record 外壳、地址/端口和双向方向；不得断言 SOAP、XML、WS-Addressing 或 WS-Security 明文，`packet_count=8`。
14. **`onvif_pcap_nic_consistency`**：同一明文 ONVIF fixture 分别输出 PCAP 并执行 NIC 捕获，断言 TCP/HTTP/80、SOAP 1.2、服务 namespace、操作、方向和动态关联一致；推荐过滤器 `tcp port 80 or tcp port 443`，`packet_count=12`。

若 tshark（抓包解析器）没有 ONVIF dissector（解析器），使用通用 `tcp`/`http`/`tls`、XML raw frames（原始帧）和稳定 namespace/操作 bytes 断言，不自创 `onvif.*` 字段。未解密 TLS 只断言 carrier。

## 4. 负例契约

每个负例必须在 planner/validator 阶段失败并传播为 task error（任务错误）；不能产生成功 PCAP、`completed/0 packet` 或只有 TCP/HTTP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `onvif_neg_xml_soap_namespace` | XML malformed、SOAP 1.2 envelope、ONVIF service namespace 或元素层级错误 | `xml`、`soap` 或 `namespace` |
| `onvif_neg_soap_action_content_type` | HTTP method、application/soap+xml、SOAPAction/action 参数与 body 操作不一致 | `soap`、`action`、`content` 或 `http` |
| `onvif_neg_addressing_body` | Action/MessageID/RelatesTo 与 body 操作、方向或响应不匹配 | `addressing`、`message`、`relates` 或 `body` |
| `onvif_neg_operation_parameter` | GetCapabilities/GetProfiles/GetStreamUri/Events 缺参数、错误 token 或错误响应 | `operation`、`parameter`、`profile`、`token` 或 `event` |
| `onvif_neg_carrier_port_family` | UDP/错误 TCP 端口、IPv4/IPv6 层链冲突、未解密 TLS 被当明文 | `carrier`、`port`、`family`、`tcp` 或 `tls` |
| `onvif_neg_correlation_error_propagation` | 跨会话 MessageID/RelatesTo、订阅 token、PullPoint 状态或错误传播错配 | `correlation`、`message`、`subscription`、`relates` 或 `match` |

负例不应污染正例 fixture；每个输入单独执行，错误必须保留原始原因，不能静默补全动态字段或以 0 包成功。

## 5. 三方一致性和静态检查

1. 设计 `67-onvif-design.md` §8、本文 §2、注册后的 `onvif.json` 和审计必须保持同一组 20 个 ID、同一顺序、14 正例+6 负例；当前 JSON 只含占位。
2. 未来 14 个正例均应有 `packet_count`/`min_packets`、carrier、方向、SOAP/XML 稳定字段和动态关联；6 个负例的 `expect` 键集合恰为 `{expect_error,error_contains}`，且 packet_count 为 `—`。
3. SOAP 1.2 envelope URI、ONVIF service namespace、HTTP content type、SOAPAction/WS-Addressing Action 和 body 操作必须一致；XML prefix 变化不能被误判为 namespace 变化。
4. Core/Discovery、GetCapabilities、GetProfiles、GetStreamUri、CreatePullPointSubscription/PullMessages 各有独立正例，profile/token、MessageID/RelatesTo 和订阅引用按会话关联。
5. WS-Security 的 UsernameToken/Timestamp/Signature 只断言结构和 opaque bytes；动态 UUID、nonce、时间、signature 不硬编码，不声称认证/签名有效。
6. IPv4/IPv6、HTTP POST/GET、明文 PCAP/NIC 和 HTTPS/TLS carrier-only 各有正例；TLS 未解密不断言 XML。
7. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/onvif.json` 应成功；当前数组只能有 `onvif_neg_unregistered`，且 `proto=onvif`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。

## 6. 实现后执行建议

注册 `onvif` layer 后，先检查 JSON parser（解析器）、层链自动补 IP、SOAP/XML namespace、HTTP header、WS-Addressing 关联、profile/token、PullPoint 状态和动态字段断言，再运行 1–14 的 PCAP/NIC 正例与 15–20 的错误传播。若环境没有 ONVIF dissector，使用通用 TCP/HTTP/TLS 字段和 raw XML bytes；不能将唯一 placeholder 的拒绝结果报告为 ONVIF suite 通过。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 ONVIF 正例和 6 个严格负例，覆盖 Core/Device/Media/Events、WS-Discovery、SOAP 1.2/XML namespace、HTTP POST/GET、WS-Addressing、WS-Security opaque、IPv4/IPv6、多会话/多流、TLS carrier 和 PCAP/NIC；不修改 Go/MCP 实现。
