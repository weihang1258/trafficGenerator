# ONVIF（网络视频接口论坛，Open Network Video Interface Forum）设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 状态：仅设计与 PCAP（抓包文件）/NIC（网卡）用例契约；`onvif` 层尚未注册，不修改 Go（编程语言）/MCP（模型上下文协议）实现，不宣称当前 suite（测试套件）可运行。  
> 配套文件：`docs/protocol-designs/67-onvif-testcase.md`、`trafficgen/test/protocol_pcap/cases/onvif.json`  
> 任务编号：67（B6 协议任务）；64-stratum（分层流量协议）为旧编号，不覆盖；本任务编号映射按任务单采用 Cwmp64、BACnet65、DOH66、ONVIF67。  
> 规范基线：ONVIF Core Specification（核心规范）、ONVIF Media Service（媒体服务）、ONVIF Device Management（设备管理）、ONVIF Events（事件服务）、WS-Discovery（Web Services 动态发现）、SOAP 1.2（简单对象访问协议版本 1.2）、WS-Addressing（Web Services 地址）和 WS-Security（Web Services 安全）。

## 1. 范围、证据等级和未注册边界

本契约覆盖 ONVIF Core（核心服务）、Device Management（设备管理）、Media（媒体服务）和 Events（事件服务）的 SOAP（简单对象访问协议，Simple Object Access Protocol）/XML（可扩展标记语言，Extensible Markup Language）消息。重点包括 WS-Discovery Probe（发现探测）、GetCapabilities（获取能力）、GetProfiles（获取媒体配置）、GetStreamUri（获取流地址）以及事件 PullPoint（拉取点）订阅和拉取。设备服务传输以 HTTP（超文本传输协议，Hypertext Transfer Protocol）POST/GET 为主；WS-Discovery Probe 依据 fixture（固定样本）声明使用 UDP/3702 发现载体或其明确的测试封装。覆盖 SOAP 1.2 envelope（信封）、XML namespace（命名空间）、`Content-Type`、WS-Addressing（Web Services 地址）和 WS-Security（Web Services 安全）不透明字段。

没有真实摄像机、媒体配置、事件源、TLS（传输层安全）解密密钥或可信安全上下文时，只断言 XML/SOAP 结构、命名空间、动作 URI、HTTP 方法/状态、方向、长度和动态字段关联；不声称设备在线、能力值真实、鉴权成功、签名有效、时间可信或媒体流已经可播放。动态 MessageID（消息标识）、UUID（通用唯一标识符）、timestamps（时间戳）、nonce（随机数）、signature（签名）和 token（令牌）使用 `presence`、`nonzero`、`distinct`、`same_as_packet` 或长度断言，不硬编码。

当前仓库没有注册 `onvif` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/onvif.json` 只能保留一个 `onvif_neg_unregistered` 注册前占位，必须 `expect_error=true` 且 `error_contains="unknown layer"`；占位不计入下文 20 个语义 ID。注册前被拒绝、0 包或空 PCAP 不是 ONVIF 行为通过。

## 2. 推荐配置、层链和载体边界

推荐明文 HTTP 层链为 `[tcp, http, onvif]`，由层链规划器自动补全 IP；本任务的稳定地址和端口为：

```json
{
  "layers": [{"tcp": {}}, {"http": {}}, {"onvif": {}}],
  "src_ip": "192.0.2.67",
  "dst_ip": "198.51.100.67",
  "src_port": 4067,
  "dst_port": 80,
  "onvif": {
    "service": "device",
    "soap_version": "1.2",
    "operation": "GetCapabilities",
    "namespace": "http://www.onvif.org/ver10/device/wsdl"
  }
}
```

| 配置项 | 约束 |
|---|---|
| `service` | `core`、`device`、`media`、`events` 或 `discovery`；操作必须属于声明的服务。 |
| `operation` | `Probe`、`GetCapabilities`、`GetProfiles`、`GetStreamUri`、`CreatePullPointSubscription`、`PullMessages` 等必须与 body、动作 URI 和响应匹配。 |
| `soap_version` | 本契约固定 SOAP 1.2；明文 HTTP 的 content type 为 `application/soap+xml`，SOAPAction 参数按 fixture 声明。 |
| `namespace` | envelope、Header、Body 和服务元素的 namespace URI 必须正确，前缀可变但 URI 不可变；禁止只凭前缀字符串判断。 |
| `addressing` | WS-Addressing 的 `Action`、`MessageID`、`To`、`RelatesTo` 按消息方向和操作关联；动态 UUID 不硬编码。 |
| `security` | WS-Security UsernameToken、Timestamp、BinarySecurityToken、Signature 只断言结构、存在和长度；没有密钥不声称验证成功。 |
| `http` | POST 携带 SOAP XML；GET 只用于明确声明的设备资源/媒体 URI 场景，不得把 GET 当 SOAP POST 的静默替代。 |
| `transport`/端口 | 明文 HTTP 使用 TCP/80；HTTPS/TCP/443 未解密只能断言 TCP/TLS carrier（载体），不断言 XML。 |
| `address_family` | IPv4 和 IPv6 为独立 fixture（固定样本）；不得从 IPv4 地址静默推导 IPv6，或让层链与地址族冲突。 |
| `session_id`/`flows` | 每会话独立 MessageID、订阅 token、RelatesTo、HTTP keep-alive 和 XML 重组缓存；多流可交织但不可跨流配对。 |
| `wire_fault` | 仅负例注入口：`xml-soap-namespace`、`soap-action-content-type`、`addressing-body`、`operation-parameter`、`carrier-port-family`、`correlation`。 |

## 3. SOAP 1.2、XML namespace 和 HTTP

SOAP 1.2 envelope 必须是 `http://www.w3.org/2003/05/soap-envelope`，包含可选 Header 和必需 Body。ONVIF 服务 namespace 依操作分别使用 Core/Device/Media/Events 的规范 URI；namespace 前缀可以是任意合法 XML 前缀，URI、元素层级、大小写和 SOAP fault（故障）结构不能改变。父元素的 XML 字符长度不得替代 HTTP `Content-Length`，XML entity（实体）转义也不能被当作业务值静默解码两次。

HTTP POST 请求的 body 是 SOAP XML，`Content-Type` 应为 `application/soap+xml`，可带 `action` 参数；响应的 HTTP status、content type 和 SOAP Body 独立判断，HTTP 200 不等于业务操作成功。HTTP/1.1 keep-alive 按 Content-Length 或 chunked framing（分块封装）分隔事务。错误响应应保持 SOAP 1.2 Fault 的 Code/Reason/Detail 结构，不以空 body 或 `completed/0 packet` 代替校验错误。

SOAPAction、WS-Addressing `Action` 和 body 操作名必须逐项一致。一个合法操作不能仅因为 HTTP header 存在就跳过 body namespace、必需参数或响应关联；未知操作、缺少必需参数、错误类型和错误 namespace 均进入对应负例。

## 4. ONVIF Core、Device、Media 和 Events

- **Core/Discovery**：WS-Discovery Probe 使用 discovery namespace、目标类型和 scope（范围）约束；ProbeMatch（探测匹配）必须在同一发现流关联 `RelatesTo`，动态 endpoint address（端点地址）只断言存在。
- **Device**：GetCapabilities 响应至少区分 Device、Media、Events 等 capability（能力）地址；地址 URI、版本和可选扩展只断言结构，不声称真实服务可达。
- **Media**：GetProfiles 返回 profile token（配置令牌）、视频/音频配置结构；GetStreamUri 请求的 profile token 与响应 URI 必须同会话关联，不把 URI 当作已建立 RTP（实时传输协议）媒体流。
- **Events**：CreatePullPointSubscription 返回订阅 reference parameters（引用参数）和 termination time（终止时间）；PullMessages 使用订阅上下文并返回 notification messages（通知消息），动态 token、UUID、时间和主题只做存在/关联断言。

GetProfiles、GetStreamUri 和事件操作的参数必须在正确的 body namespace 内，响应操作不能被错误请求类型替换。PullPoint 的订阅状态按流隔离；多订阅可交织，但 `SubscriptionReference`、MessageID、RelatesTo 和通知序号不得跨流复用。

## 5. WS-Addressing、WS-Security 和动态字段

WS-Addressing Header 的 `Action`、`MessageID`、`To`、可选 `ReplyTo` 和响应 `RelatesTo` 是 XML 元素，不是任意 HTTP header。请求/响应的 `RelatesTo` 应 `same_as_packet` 对应请求 MessageID；不同会话的 MessageID/UUID 应 `distinct`。运行时 UUID、订阅 token 和通知时间禁止写入固定期望值。

WS-Security Header 可包括 `UsernameToken`、`Nonce`、`Created`、`BinarySecurityToken`、`Timestamp` 和 XML Signature。没有密钥和证书链时，只断言 namespace、元素层级、算法 URI、签名/令牌 bytes 的存在、长度和不透明边界；不把 base64 文本、签名 bytes 或 timestamp 当作可硬编码常量，也不声称签名验证、时间窗口或用户认证成功。

TLS 未解密时，PCAP/NIC 只能断言 Ethernet/IP/TCP/TLS carrier、端口和方向；禁止断言 SOAP/XML、WS-Addressing 或 WS-Security 明文内容。

## 6. IPv4/IPv6、多会话、多流与 PCAP/NIC

IPv4 fixture 断言 `ip.proto=6`、192.0.2.67/198.51.100.67、TCP/80 和 HTTP 方向；IPv6 fixture 断言最终 next header（下一报头）为 TCP、独立 IPv6 地址族、TCP 端口和同样的 SOAP carrier。无 VLAN/IP/TCP options 时，IPv4 TCP payload 参考 offset（偏移）为 `14+20+20=54`，IPv6 为 `14+40+20=74`；固定 offset 只适用于明确 fixture，TCP 分段必须先重组。

至少两个独立会话和多个并行流应有独立四元组、MessageID、RelatesTo、profile token、subscription reference、通知状态和重组缓存。全局包序可交织，响应只按流内关联；同一设备地址不意味着可以共享会话状态。

PCAP（离线抓包）和 NIC（真实网卡捕获）必须使用同一明文 fixture，断言 TCP/HTTP、80/443、方向、SOAP/XML 稳定字段以及动态关联一致。推荐 NIC 过滤器为 `tcp port 80 or tcp port 443`，并记录 checksum offload（校验和卸载）差异。HTTPS 不解密时仅断言 TLS carrier。

## 7. 错误处理、负例和完成定义

6 个语义负例必须在 planner/validator 阶段失败并传播为 task error（任务错误），不能输出成功 PCAP、`completed/0 packet` 或只有 TCP/HTTP 外壳的假成功。未来注册后的负例 `expect` 键集合严格为 `{"expect_error", "error_contains"}`；当前 JSON 仅含注册占位。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `onvif_neg_xml_soap_namespace` | XML malformed、SOAP 1.2 envelope 或 ONVIF service namespace 错误/缺失 | `xml`、`soap` 或 `namespace` |
| `onvif_neg_soap_action_content_type` | HTTP method/content type、SOAPAction/action 参数与操作不一致 | `soap`、`action`、`content` 或 `http` |
| `onvif_neg_addressing_body` | WS-Addressing Action/MessageID/RelatesTo 与 body 操作、方向或响应不匹配 | `addressing`、`message`、`relates` 或 `body` |
| `onvif_neg_operation_parameter` | GetCapabilities/GetProfiles/GetStreamUri/事件操作缺参数、错误 token 或错误响应关联 | `operation`、`parameter`、`profile`、`token` 或 `event` |
| `onvif_neg_carrier_port_family` | UDP/错误 TCP 端口、IPv4/IPv6 层链冲突、未解密 TLS 被当明文 | `carrier`、`port`、`family`、`tcp` 或 `tls` |
| `onvif_neg_correlation_error_propagation` | 跨会话 MessageID/RelatesTo、订阅 token、PullPoint 状态或错误传播错配 | `correlation`、`message`、`subscription`、`relates` 或 `match` |

实现完成定义：注册 `onvif` layer；实现 SOAP 1.2/XML namespace、HTTP POST/GET、Core/Device/Media/Events、WS-Discovery、WS-Addressing、WS-Security opaque 字段、IPv4/IPv6、多会话/多流及 planner→worker→PCAP/NIC 正负完整传播；-race（竞态检测）和集成测试覆盖全部 20 个语义 ID。TLS 在没有解密实现时保持 carrier-only（仅载体）断言。

## 8. 20 个语义场景和 packet_count 映射

共 20 个唯一语义 ID：14 个正例和 6 个负例；顺序必须与 `67-onvif-testcase.md` §2 及注册后的 `onvif.json` 完全一致。当前 JSON 只有不计数的注册前置占位。

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

三方契约必须保持本文 §8、`67-onvif-testcase.md` §2、注册后的 `onvif.json` 同一组 20 个 ID、同一顺序、14 正例+6 负例；当前 JSON 另有一个不计数的 `onvif_neg_unregistered`，且唯一预期为 `unknown layer`。

## 9. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 ONVIF 正例和 6 个严格负例，覆盖 Core/Device/Media/Events、WS-Discovery、SOAP 1.2/XML namespace、HTTP POST/GET、WS-Addressing、WS-Security opaque、IPv4/IPv6、多会话/多流、TLS carrier 和 PCAP/NIC；不修改 Go/MCP 实现。
