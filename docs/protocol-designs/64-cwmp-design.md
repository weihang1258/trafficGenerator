# CWMP（CPE 广域网管理协议，CPE WAN Management Protocol）/TR-069 设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 状态：仅设计与 PCAP（抓包文件）/NIC（网卡）用例契约；`cwmp` 层尚未注册，不修改 Go（编程语言）或 MCP（模型上下文协议）实现，不宣称当前测试套件可运行。  
> 配套文件：`docs/protocol-designs/64-cwmp-testcase.md`、`trafficgen/test/protocol_pcap/cases/cwmp.json`  
> 规范基线：TR-069 Amendment 6、SOAP（简单对象访问协议，Simple Object Access Protocol）1.1、HTTP（超文本传输协议，Hypertext Transfer Protocol）/1.1；XML（可扩展标记语言，Extensible Markup Language）命名空间使用 SOAP 1.1 与 CWMP 规范定义值。

## 1. 范围、证据等级和未注册边界

本契约定义 CPE（用户驻地设备，Customer Premises Equipment）与 ACS（自动配置服务器，Auto-Configuration Server）之间的 CWMP 会话：SOAP 1.1 Envelope（信封）、Header（头）和 Body（体），Inform/InformResponse，事件码、ParameterKey（参数键）、参数读写，Download/Upload、TransferComplete、Reboot、FactoryReset 与 Fault。载体覆盖 HTTP/1.1 明文、HTTPS（基于 TLS 的 HTTP，HTTP over Transport Layer Security）不解密观察、IPv4/IPv6、多会话/多流，以及 PCAP/NIC 一致性。

当前仓库没有注册 `cwmp` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/cwmp.json` 只保留一个不计入 20 个语义 ID 的 `cwmp_neg_unregistered` 注册前占位，必须 `expect_error=true` 且 `error_contains="unknown layer"`。注册前拒绝、0 包、空 PCAP 或只有 TCP/HTTP 外壳都不是 CWMP 行为通过。

动态字段禁止硬编码：SOAP `cwmp:ID`、会话 Cookie（会话标识）、DeviceId（设备标识）的 Manufacturer/OUI（组织唯一标识符）/ProductClass（产品类别）/SerialNumber（序列号）、CommandKey（命令键）、ParameterKey、RetryCount、Transfer URL 与时间戳使用 `presence`（存在）、`nonzero`（非零）、`distinct`（彼此不同）、`same_as_packet`（与指定包相同）或类型/长度断言。没有 ACS/CPE 身份材料时，不声称设备真实身份或远程操作已执行。

## 2. 推荐层链、地址与载体

推荐明文层链为 `[tcp, http, cwmp]`（引擎自动补 IPv4；需要显式地址族时使用 `[ip, tcp, http, cwmp]` 或 IPv6 等价链）：

```json
{
  "layers": [{"tcp": {}}, {"http": {}}, {"cwmp": {}}],
  "src_ip": "192.0.2.65",
  "dst_ip": "198.51.100.65",
  "src_port": 50065,
  "dst_port": 7547,
  "cwmp": {"version": "1.0", "soap_version": "1.1", "profile": "tr-069-am6"}
}
```

| 配置/载体 | 约束 |
|---|---|
| `version`/`profile` | 本契约以 TR-069 Amendment 6、CWMP 1.0 语义为基线；不把 TR-181 或厂商扩展冒充基础 RPC（远程过程调用，Remote Procedure Call）。 |
| `transport`/端口 | 明文 HTTP 使用 TCP/7547；HTTPS 也使用 TCP/7547。端口 7547 是 fixture（固定样本）约定，不是唯一协议识别证据。 |
| `layers` | 推荐顺序 `tcp → http → cwmp`；IPv4/IPv6 用独立 fixture。不能以 UDP、裸 CWMP 或私有长度前缀替代 HTTP SOAP carrier（载体）。 |
| HTTPS | 未提供 TLS 解密密钥时，只断言 TCP/7547、TLS 握手/记录存在、方向和会话隔离；不得断言明文 HTTP、SOAP XML 或 RPC 字段。 |
| HTTP | SOAP 1.1 使用 `POST`；明文 Content-Type（内容类型）为 `text/xml`，可带 `charset`; SOAPAction（SOAP 动作）可观察但不能取代 XML Body。请求/响应 Content-Length 或合法 chunked framing（分块封装）必须自洽。 |
| 会话 | Cookie、HTTP keep-alive（持久连接）、`cwmp:ID`、HoldRequests 和设备标识按 TCP stream（字节流）隔离；多流可交织但不得跨流关联。 |
| `wire_fault` | 仅负例注入口：`xml`、`soap`、`http`、`rpc`、`header`、`carrier`、`propagation`。 |

## 3. SOAP 1.1 Envelope 与 CWMP Header

每个 HTTP SOAP Body 是完整 XML 文档；SOAP 1.1 Envelope 命名空间为 `http://schemas.xmlsoap.org/soap/envelope/`，CWMP 命名空间使用 TR-069 定义的版本 URI（统一资源标识符，Uniform Resource Identifier）。基本结构为：

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
              xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
  <soap:Header>
    <cwmp:ID soap:mustUnderstand="1">运行期动态 ID</cwmp:ID>
    <cwmp:HoldRequests>0</cwmp:HoldRequests>
  </soap:Header>
  <soap:Body>
    <cwmp:Inform>...</cwmp:Inform>
  </soap:Body>
</soap:Envelope>
```

`cwmp:ID` 在请求与对应响应之间必须匹配；不同会话即使偶然类型相同也必须使用 distinct 关联，不能使用固定数字替代。`soap:mustUnderstand="1"` 的 Header 语义要保持，缺失、错误 namespace、重复 ID 或响应错配进入负例。`HoldRequests` 取布尔语义的 `0/1` 文本并按声明类型断言，不因空值静默默认。

SOAP Fault（故障）使用 SOAP 1.1 Fault 结构：`faultcode`、`faultstring`、可选 `detail`；CWMP Fault 在 `detail` 中含 `FaultCode`、`FaultString`、可选 Fault 要素数组。不能把 HTTP 200 当成 RPC 成功，也不能把 SOAP Fault 伪装成正常响应。

XML namespace、元素大小写、必需元素、顺序、父子封装和 XML escaping（转义）均按实际解析结果断言。HTTP 分段不是 XML 消息边界；TCP 重组后才能解析完整 SOAP 文档。

## 4. Inform、事件码、设备标识和 ParameterKey

CPE 启动或周期上报时发送 `cwmp:Inform`，至少包含：

- `DeviceId`：Manufacturer、OUI、ProductClass、SerialNumber；四者存在且类型/长度合法，具体设备值动态断言。
- `EventList`：一个或多个 Event，事件码覆盖 `0 BOOTSTRAP`、`1 BOOT`、`2 PERIODIC`、`4 VALUE CHANGE`、`6 KICKED`、`7 CONNECTION REQUEST`、`8 TRANSFER COMPLETE`、`9 DIAGNOSTICS COMPLETE` 等声明值；事件码与 CommandKey 可按 fixture 组合。
- `MaxEnvelopes`：正整数边界；`CurrentTime` 与 `RetryCount` 结构存在，时间不硬编码。
- `ParameterList`：参数名、值和 `xsi:type`（XML Schema 类型声明）按实际类型观察；不把设备标识或参数值写成固定现实设备资料。

ACS 返回 `cwmp:InformResponse`，包含 `MaxEnvelopes`，其 `cwmp:ID` 必须与 Inform 请求相同。`ParameterKey` 是 ACS 对一组参数修改的关联键：SetParameterValues 请求中的值在后续响应或相关事件中保持 same-as；空 ParameterKey 是合法边界时必须保持为空，不能被随机值覆盖。

## 5. 参数 RPC 与操作 RPC

### 5.1 Get/SetParameterValues

`GetParameterValues` 请求携带 ParameterNames 数组，响应携带 ParameterList。`SetParameterValues` 请求携带 Name/Value 对和 ParameterKey，响应返回 `Status`（0=未应用、1=已应用）及同一 `cwmp:ID`。参数列表顺序、重复名、空列表和 `xsi:type` 必须按配置验证；不能以 TCP 顺序代替 RPC 关联。

### 5.2 Download/Upload/TransferComplete

ACS 的 `Download` 至少含 CommandKey、FileType、URL、FileSize、TargetFileName、四类时间/延迟字段；URL、文件名、命令键和时间为动态或 fixture 字段，只断言 presence、类型、长度和关联。CPE 返回 DownloadResponse 的 Status、StartTime、CompleteTime，并在完成后发送 `TransferComplete`，其 FaultStruct 可为空或包含 FaultCode/FaultString。

`Upload` 方向相反：CPE 发送 Upload 请求，ACS 返回 UploadResponse；随后 TransferComplete 仍需按同一 CommandKey/transfer 上下文关联。没有真实文件服务器时，只断言 RPC 结构、方向和动态关联，不声称文件已上传/下载或校验成功。

### 5.3 Reboot、FactoryReset 与 Fault

`Reboot` 与 `FactoryReset` 请求必须有 CommandKey；响应按 `cwmp:ID` 关联。FactoryReset 是破坏性操作的协议表示，不代表测试真的重置设备。错误响应使用 SOAP Fault + CWMP Fault；FaultCode/FaultString 只断言存在、类型、边界和请求关联，不硬编码厂商错误文本。

## 6. HTTP/1.1、keep-alive、TLS 和多流

明文请求必须为 HTTP/1.1 POST，URI、Host、SOAPAction、Content-Type 和 Content-Length 与 SOAP XML body 长度自洽；响应 status、Content-Type、Content-Length/Transfer-Encoding、Connection 按实际封装断言。一个 keep-alive TCP stream 可以连续承载 Inform、InformResponse 及 ACS RPC；每个 HTTP 消息按 Content-Length 或合法 chunked 规则分隔，不能以 TCP PSH 或 packet_count 作为边界。

HTTPS 明文不可见时，测试只断言 TCP/7547、TLS ClientHello/ServerHello 或记录方向、连接建立/关闭和多流隔离；不把密文 bytes 解读为 SOAP、HTTP method、Cookie 或 cwmp:ID。IPv4 使用 `ip.proto=6`，IPv6 使用 TCP next header；没有 IP/TCP options 的 fixture 参考 payload 偏移仅为 IPv4 `14+20+20=54`、IPv6 `14+40+20=74`，不得当作通用 CWMP record header。

每个 session（会话）独立保存 Cookie、cwmp:ID 映射、DeviceId、ParameterKey、CommandKey、RPC 状态和 HTTP body 缓存。多 session/多流可以共享端口但不可共享动态字段；全局 PCAP 包序交织不改变流内关联。

## 7. 错误处理、PCAP/NIC 证据和完成定义

6 个语义负例必须在 planner/validator 阶段失败并传播为 task error（任务错误），不能生成成功 PCAP、`completed/0 packet` 或只有 TCP/HTTP 外壳的假成功。负例执行期 `expect` 只允许 `expect_error` 与 `error_contains`；本契约中的 packet_count 对负例统一写 `—`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `cwmp_neg_xml_soap` | XML 不完整/非法、SOAP namespace/Envelope/Body/Header、必需元素或 Fault 结构错误 | `xml`、`soap` 或 `envelope` |
| `cwmp_neg_http_method_content_type` | 非 POST、错误 HTTP 版本、Content-Type/Content-Length/Transfer-Encoding 与 SOAP body 不符 | `http`、`method` 或 `content-type` |
| `cwmp_neg_rpc_status_boundary` | 未声明 RPC、必填参数缺失、Status/FaultCode/MaxEnvelopes/ParameterKey 边界或类型错误 | `rpc`、`status`、`parameter` 或 `boundary` |
| `cwmp_neg_header_idempotency` | cwmp:ID 响应错配/重复、mustUnderstand 错误、Cookie/CommandKey/ParameterKey 跨流污染 | `header`、`id`、`match` 或 `session` |
| `cwmp_neg_carrier_tls` | UDP/错误端口/错误层链、HTTPS 密文被要求解析明文、TLS carrier 配置不一致 | `carrier`、`tcp`、`tls` 或 `profile` |
| `cwmp_neg_error_propagation` | planner/worker 生成失败、无效 RPC 被吞掉、任务错误被伪报 completed/0 packet | `propagate`、`planner`、`worker` 或 `task` |

PCAP/NIC 正例只断言可观察事实：TCP carrier、7547 端口、方向、HTTP method/header（明文时）、SOAP Envelope namespace、Header/Body 结构、RPC 名称、动态 ID/设备标识/命令键的存在与关联、IPv4/IPv6 和会话隔离。HTTPS 未解密只断言 TLS carrier。NIC 捕获记录 checksum offload（校验和卸载）可能造成的显示差异，不因校验和显示差异否定应用字段。

实现完成定义：注册 `cwmp` layer；实现 SOAP 1.1/XML 编排、Inform/InformResponse、事件码、ParameterKey、Get/SetParameterValues、Download/Upload/TransferComplete、Reboot/FactoryReset、Fault、HTTP/HTTPS carrier 和会话状态；planner→worker→PCAP/NIC output（输出）正负完整传播；测试覆盖 IPv4/IPv6、keep-alive、多会话/多流、动态字段和错误传播；未解密 TLS 不声称 SOAP 已验证。

## 8. 20 个语义场景和 packet_count 映射

共 20 个唯一语义 ID：14 个正例和 6 个负例。顺序必须与 `64-cwmp-testcase.md` §2 及注册后的 `cwmp.json` 完全一致；当前 JSON 只有不计数的注册前置占位。

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

三方契约必须保持本文 §8、`64-cwmp-testcase.md` §2、注册后的 `cwmp.json` 同一组 20 个 ID、同一顺序、14 正例+6 负例；当前 JSON 另有一个不计数的 `cwmp_neg_unregistered`，且唯一预期为 `unknown layer`。

## 9. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 TR-069 Amendment 6/SOAP 1.1/HTTP 1.1 正例和 6 个严格负例，覆盖 Inform、事件码、参数 RPC、文件传输、重启/恢复出厂、Fault、Header 幂等性、keep-alive、HTTPS opaque、IPv4/IPv6、多会话/多流、PCAP/NIC 与错误传播；不修改 Go/MCP 实现。
