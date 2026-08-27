# CWMP（CPE 广域网管理协议，CPE WAN Management Protocol）测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/64-cwmp-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/cwmp.json`  
> 状态：`cwmp` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前测试套件可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§8 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `cwmp_neg_unregistered`，其 `expect` 必须 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

基线为 TR-069 Amendment 6、SOAP（简单对象访问协议，Simple Object Access Protocol）1.1、HTTP（超文本传输协议，Hypertext Transfer Protocol）/1.1，TCP/7547 为推荐载体。明文 HTTP 才能断言 XML（可扩展标记语言，Extensible Markup Language）、SOAP、RPC（远程过程调用，Remote Procedure Call）和 Header（头）；HTTPS（基于 TLS 的 HTTP，HTTP over Transport Layer Security）未解密时只断言 TCP/TLS carrier（载体）、方向、端口和会话，不解读密文为 SOAP。

SOAP `cwmp:ID`、Cookie（会话标识）、DeviceId（设备标识）、CommandKey（命令键）、ParameterKey（参数键）、Transfer URL 与时间戳均为动态字段，使用 `presence`（存在）、`nonzero`（非零）、`distinct`（不同）、`same_as_packet`（同包值）或类型/长度断言。没有真实设备、ACS（自动配置服务器，Auto-Configuration Server）或文件服务器证据时，不声称身份、重启、恢复出厂、上传下载或签名操作现实成功。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `cwmp_inform_ipv4` | 正 | IPv4/7547、SOAP Inform、DeviceId/EventList/ParameterList | 12 |
| 2 | `cwmp_inform_response` | 正 | InformResponse、MaxEnvelopes、SOAP ID 关联 | 8 |
| 3 | `cwmp_event_codes_parameter_key` | 正 | 事件码集合、ParameterKey 非空/空边界和关联 | 10 |
| 4 | `cwmp_get_parameter_values` | 正 | GetParameterValues 请求/响应、参数名和值类型 | 10 |
| 5 | `cwmp_set_parameter_values` | 正 | SetParameterValues、Status 0/1、ParameterKey | 10 |
| 6 | `cwmp_download_transfer_complete` | 正 | Download、TransferComplete、CommandKey/Transfer FaultStruct | 16 |
| 7 | `cwmp_upload_transfer_complete` | 正 | Upload、UploadResponse、TransferComplete 关联 | 16 |
| 8 | `cwmp_reboot_factory_reset` | 正 | Reboot/FactoryReset、动态 CommandKey 和响应 | 16 |
| 9 | `cwmp_fault_soap_header_idempotency` | 正 | SOAP Fault/CWMP Fault、mustUnderstand、ID 幂等关联 | 12 |
| 10 | `cwmp_http_keepalive` | 正 | HTTP/1.1 POST、Content-Length、连续多 RPC 与 keep-alive | 18 |
| 11 | `cwmp_https_tls_opaque` | 正 | HTTPS/TLS 不解密，仅断言 7547 carrier 和记录方向 | 10 |
| 12 | `cwmp_ipv6_multi_session` | 正 | IPv6、多个 session/stream、Cookie/ID/DeviceId 隔离 | 24 |
| 13 | `cwmp_multi_flow_dynamic_fields` | 正 | 多流并发、动态 ID/设备标识/命令键和响应匹配 | 24 |
| 14 | `cwmp_pcap_nic_consistency` | 正 | PCAP/NIC 同 fixture 的 TCP/HTTP/SOAP 观察一致性 | 16 |
| 15 | `cwmp_neg_xml_soap` | 负 | XML/SOAP namespace、Envelope、Body/Header/Fault 错误 | — |
| 16 | `cwmp_neg_http_method_content_type` | 负 | HTTP method、版本、Content-Type、长度/分块错误 | — |
| 17 | `cwmp_neg_rpc_status_boundary` | 负 | RPC、状态码、必填字段和边界类型错误 | — |
| 18 | `cwmp_neg_header_idempotency` | 负 | SOAP ID/mustUnderstand、Cookie/ParameterKey/跨流状态错配 | — |
| 19 | `cwmp_neg_carrier_tls` | 负 | 载体、端口、层链和未解密 TLS 误解析错误 | — |
| 20 | `cwmp_neg_error_propagation` | 负 | planner/worker/task 错误传播与 0 包假成功 | — |

## 3. 正例逐项断言契约

1. **`cwmp_inform_ipv4`**：使用 `192.0.2.65`/`198.51.100.65` 的 IPv4/TCP/7547 fixture，断言三次握手、HTTP/1.1 POST、`Content-Type: text/xml`、SOAP 1.1 Envelope/`cwmp:Inform`，DeviceId 四字段、EventList、MaxEnvelopes、CurrentTime、RetryCount 和 ParameterList 存在。设备标识和时间只做动态 presence/类型/长度断言，`packet_count=12`。
2. **`cwmp_inform_response`**：ACS 返回 `InformResponse`，断言 SOAP Header 的 `cwmp:ID` 与 Inform 请求 same_as、Body 含 MaxEnvelopes、HTTP 200 和正确 Content-Length；不以 HTTP 200 单独证明 RPC 成功，`packet_count=8`。
3. **`cwmp_event_codes_parameter_key`**：覆盖 BOOTSTRAP、BOOT、PERIODIC、VALUE CHANGE、KICKED、CONNECTION REQUEST、TRANSFER COMPLETE 等声明事件码，以及非空/空 ParameterKey 边界；断言事件项结构、CommandKey 关联和同会话状态，动态键不硬编码，`packet_count=10`。
4. **`cwmp_get_parameter_values`**：断言 GetParameterValues 的 ParameterNames 数组、响应 ParameterList、Name/Value/`xsi:type` 类型和请求响应 ID matching（匹配）；不依赖全局包序，`packet_count=10`。
5. **`cwmp_set_parameter_values`**：断言 SetParameterValues 的 Name/Value 对、`xsi:type`、ParameterKey 和响应 Status=0/1 的合法边界；响应 ID 与请求相同，ParameterKey 使用 same_as，`packet_count=10`。
6. **`cwmp_download_transfer_complete`**：断言 ACS→CPE Download 的 CommandKey、FileType、URL、FileSize、TargetFileName、时间/延迟字段，DownloadResponse 及后续 TransferComplete 的同 CommandKey/FaultStruct 关联；不声称文件真实下载，`packet_count=16`。
7. **`cwmp_upload_transfer_complete`**：断言 CPE→ACS Upload、UploadResponse、TransferComplete 的方向、CommandKey、URL/文件字段和状态关联；动态 URL/时间只 presence/类型，`packet_count=16`。
8. **`cwmp_reboot_factory_reset`**：同会话或独立 RPC 覆盖 Reboot 与 FactoryReset，断言 CommandKey、SOAP ID、响应方向和 HTTP framing；操作只表示协议请求，不声称设备真的重启或清空，`packet_count=16`。
9. **`cwmp_fault_soap_header_idempotency`**：断言 SOAP 1.1 Fault 的 faultcode/faultstring/detail、CWMP FaultCode/FaultString、`soap:mustUnderstand="1"` 和重复请求的 ID 幂等关联；错误文本不硬编码，`packet_count=12`。
10. **`cwmp_http_keepalive`**：在一个 HTTP/1.1 TCP stream 上连续承载 Inform、InformResponse 与至少两个 ACS RPC，断言 POST、Host、SOAPAction、Content-Length/合法分块、`Connection: keep-alive` 和按长度重组的 SOAP 文档；TCP segment/PSH 不是消息边界，`packet_count=18`。
11. **`cwmp_https_tls_opaque`**：使用 TCP/7547 的 TLS fixture，断言握手/记录、双向方向、关闭和会话状态；未解密时不断言 HTTP method、Cookie、SOAP XML 或 cwmp:ID，`packet_count=10`。
12. **`cwmp_ipv6_multi_session`**：至少两个 IPv6 TCP/7547 session/stream，断言 IPv6 TCP next header、各自 Cookie、cwmp:ID、DeviceId、Inform 状态和响应关联隔离；不继承 IPv4 fixture 或跨流动态字段，`packet_count=24`。
13. **`cwmp_multi_flow_dynamic_fields`**：至少两个并发流覆盖 Inform、Set/Get、Download 或 Reboot，断言每流独立 HTTP 事务、ID、DeviceId、ParameterKey、CommandKey、Cookie 和响应 matching；允许全局包交织，动态值 presence/distinct/same_as，`packet_count=24`。
14. **`cwmp_pcap_nic_consistency`**：同一明文 fixture 分别输出 PCAP 并进行 NIC 捕获，断言 TCP/7547、方向、HTTP POST/header、SOAP Envelope、RPC 名称、ID/ParameterKey 关联和 IPv4/IPv6 事实一致；记录 checksum offload 差异，`packet_count=16`。

没有 TLS 解密密钥时，不添加“SOAP 已解析”“HTTP header 可见”或固定 Cookie/ID/设备序列号断言。若环境没有 CWMP dissector（解析器），使用 `tcp`、`http`、`tls`、XML raw bytes（原始字节）和稳定的方向/长度断言，不自创字段名。

## 4. 负例契约

每个负例必须在 planner/validator 阶段失败并传播为 task error；不能产生成功 PCAP、`completed/0 packet` 或只有 TCP/HTTP 外壳的假成功。执行期 `expect` 键集合严格为 `{expect_error, error_contains}`，本节负例的 `packet_count` 均为 `—`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `cwmp_neg_xml_soap` | XML 不完整/非法、SOAP namespace/Envelope/Body/Header、必需元素或 Fault 结构错误 | `xml`、`soap` 或 `envelope` |
| `cwmp_neg_http_method_content_type` | 非 POST、错误 HTTP 版本、Content-Type/Content-Length/Transfer-Encoding 与 SOAP body 不符 | `http`、`method` 或 `content-type` |
| `cwmp_neg_rpc_status_boundary` | 未声明 RPC、必填参数缺失、Status/FaultCode/MaxEnvelopes/ParameterKey 边界或类型错误 | `rpc`、`status`、`parameter` 或 `boundary` |
| `cwmp_neg_header_idempotency` | cwmp:ID 响应错配/重复、mustUnderstand 错误、Cookie/CommandKey/ParameterKey 跨流污染 | `header`、`id`、`match` 或 `session` |
| `cwmp_neg_carrier_tls` | UDP/错误端口/错误层链、HTTPS 密文被要求解析明文、TLS carrier 配置不一致 | `carrier`、`tcp`、`tls` 或 `profile` |
| `cwmp_neg_error_propagation` | planner/worker 生成失败、无效 RPC 被吞掉、任务错误被伪报 completed/0 packet | `propagate`、`planner`、`worker` 或 `task` |

合法的动态 ID、Cookie、DeviceId、CommandKey、ParameterKey、时间、空 ParameterKey、Status 0/1、Transfer FaultStruct 和 HTTPS opaque carrier 已由正例覆盖，不能在负例中硬编码或污染正例。错误传播必须保留原始原因，不能以通用“0 packets”替代验证错误。

## 5. 三方一致性和静态检查

1. 设计 `64-cwmp-design.md` §8、本文 §2、注册后的 `cwmp.json` 和审计必须保持同一组 20 个 ID、同一顺序：14 正例 + 6 负例；当前 JSON 另有一个不计入的 `cwmp_neg_unregistered` 占位。
2. 未来 14 个正例均有 `packet_count`/`min_packets`、HTTP/TCP 或 TLS carrier、方向和动态字段关联；6 个负例的 `expect` 键集合必须恰为 `{expect_error, error_contains}`，不添加 `packet_count`。
3. SOAP 1.1 Envelope/Header/Body、CWMP namespace、`cwmp:ID`、`soap:mustUnderstand` 和 Fault detail 必须按真实 XML 结构断言；HTTP 200 不替代 RPC 状态。
4. Inform/InformResponse 的 DeviceId、EventList、MaxEnvelopes、CurrentTime、RetryCount、ParameterList，及 Get/Set 的参数名/值/`xsi:type`、Status、ParameterKey 必须逐字段覆盖。
5. Download/Upload/TransferComplete、Reboot、FactoryReset 的方向、CommandKey、状态和 FaultStruct 必须关联；不声称文件或设备现实操作成功。
6. HTTP/1.1 POST、Content-Type、Content-Length/合法 chunked、keep-alive 按 TCP stream 重组；TCP segment、PSH 或 packet_count 不能替代 SOAP 消息边界。
7. IPv4/IPv6、多会话/多流各自隔离 Cookie、ID、DeviceId、ParameterKey、CommandKey 和 RPC 状态；HTTPS 未解密只断言 TLS carrier。
8. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/cwmp.json` 应成功；当前数组只能含 `cwmp_neg_unregistered`，且 `proto=cwmp`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。
9. 未来注册后，20 个语义 case（用例）必须按本文 §2 顺序加入；负例 `expect` 只能有 `expect_error`、`error_contains`，占位不计入 20 个 ID。

## 6. 实现后执行建议

注册 `cwmp` layer 后，先检查 JSON parser（解析器）、层链、HTTP framing、XML/SOAP namespace、Header/Body、ID/ParameterKey/CommandKey 关联和 14+6 顺序，再运行 1–14 的 PCAP/NIC 正例与 15–20 的错误传播。HTTPS 无解密材料时仅运行 TLS carrier 断言；不能将唯一 placeholder 的拒绝结果报告为 CWMP suite 通过。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 TR-069 Amendment 6/SOAP 1.1/HTTP 1.1 正例和 6 个严格负例，覆盖 Inform、事件码、ParameterKey、参数与文件传输 RPC、重启/恢复出厂、Fault、Header 幂等性、keep-alive、HTTPS opaque、IPv4/IPv6、多会话/多流、PCAP/NIC 与错误传播；不修改 Go/MCP 实现。
