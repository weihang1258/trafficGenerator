# ONVIF（网络视频接口论坛，Open Network Video Interface Forum）测试用例契约

> 版本：v2.0.1（测试用例）
> 日期：2026-09-01
> 配套设计：`docs/protocol-designs/67-onvif-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/onvif.json`（proto key：`onvif`；本版不写文件，当前 JSON 仅含注册前置占位）
> 状态：**独立隔离对抗审查已完成**（按《协议设计文档与用例文档需求文档 v1.1》§3 流程：独立审查 agent 三向审计 9 项清单 → 修复 → 复验 clean，含复验新发现 2 项 MINOR 的修复复验；审查/修复记录见 §9 修订记录 v2.0.0/v2.0.1）。
> 修订记录：v2.0.1（2026-09-01）：按独立隔离审查 9 项问题清单修复（详见 §9）；v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写/review，取代 2026-08-20 旧稿（旧稿见 git 历史）。

## 1. 测试原则和未注册边界

用例从设计 §2–§9 逐项派生，共 32 个唯一语义 ID：21 个正例 + 11 个负例。派生规则：设计 §3 每个编码条款、§5 每个状态/事务行为、§7 每行错误处理在本文有对应断言；断言不得超出设计（并追溯到 ONVIF Core Spec / SOAP 1.2 / WSDL）声明范围。**一个用例只验证一个协议行为**（v1.1 §7 原子原则）：每服务每操作、每 SOAP 编码规则、每 WS-Addressing 关联规则、每边界、每错误分支各一。

当前 JSON 只保留一个 `onvif_neg_unregistered` 注册前置占位：`proto=onvif`、`expect_error=true`、`error_contains` 精确为 `unknown layer`；该占位不计入 32 个语义 ID，不得把拒绝、0 包或空 PCAP 报告为 ONVIF 行为通过。注册后移除占位，再按本文 §2 顺序补入 21 个正例与 11 个负例。

**TSHARK 实测基线（本机 3.6.14，`-G fields`/`-G protocols` 核验，非臆造）**：本机**没有 ONVIF/WS-* 专用 dissector（解析器）**，不存在任何 `onvif.*`、`soap.*`、`wsa.*` 字段，**不得臆造**。可用字段为：`http.request.method`、`http.request.uri`、`http.request.uri.path`、`http.request.line`、`http.response.code`、`http.response.line`、`http.content_type`、`http.content_length`、`http.content_length_header`、`http.file_data`（FT_STRING，body 原始字节）、`http.host`、`http.connection`、`http.authorization`、`http.www_authenticate`、`http.cache_control`、`tcp.stream`、`tcp.len`、`tcp.flags.*`、`ip.version`、`ipv6.nxt`。SOAP/XML 内容断言走两条路：① `http.file_data` 存在性（fields 断言 nonzero）；② raw frame（原始帧）body 起点稳定 ASCII 前缀与关键字节的 hex 断言（`frames` 的 `offset/hex`，见 §3）。XML 通用 dissector（`xml.tag`/`xml.attribute`）存在于 `-G fields` 清单，但 tshark 3.6.14 是否对 `application/soap+xml` 的 HTTP body 自动内层 XML 解码**未实证**——实现期先实证，可用则作为 `http.file_data` 的辅助旁证，未实证前**只用 `http.*` + frames hex 双通道断言，不把 `xml.*` 写进最低断言集**。

**动态字段禁止硬编码**：`wsa:MessageID`（`urn:uuid:` 形态）、Nonce、Created/CurrentTime/TerminationTime（dateTime）、digest 摘要、订阅地址用 `nonzero`、`distinct_values`、`same_as_packet` 或帧字节前缀断言；Manufacturer/Model/SerialNumber/ProfileToken/token 名、URI 路径、MediaUri 文本为预配置值，允许 fixture 显式给出。不声称设备真实身份/能力值/认证成功/签名有效/媒体流可播放；TLS 未解密时只断言 TLS/TCP 外层（本版无 HTTPS 语义用例，见设计 §1 边界）。

**包数约定**（设计 §9 完成定义）：HTTP/1.1 单事务（1 请求 + 1 响应，各单段）= 3（SYN/SYN-ACK/ACK）+ N（承载 HTTP 消息的 TCP 分段数）+ 4（双向 FIN/ACK，FIN+ACK×2+FIN/ACK）＝ 3+2+4 = **9**。多事务（M 笔，各单段）= 3 + 2M + 4。401 往返（含无凭据请求 + 带凭据请求两事务）= 3 + 4 + 4 = **11**。多会话 = 各会话之和，第二会话包号起点 = 前会话总包数 + 1（设计 §5 多会话展开）。跨 MSS 分段每加 1 段 +1。实现期以实际输出校准 packet_count，断言以 fields/frames 为准；负例无 packet_count。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖（设计 §） | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `onvif_ipv4_get_system_date_and_time` | 正 | §3.5/§4①：IPv4 单流基线、PRE_AUTH GetSystemDateAndTime | 9 |
| 2 | `onvif_device_get_capabilities` | 正 | §3.5/§4①：GetCapabilities、Category、XAddr 结构 | 9 |
| 3 | `onvif_device_get_device_information` | 正 | §3.5/§4②：GetDeviceInformation 五字段 | 9 |
| 4 | `onvif_device_get_network_interfaces` | 正 | §3.5/§4②：GetNetworkInterfaces 数组 | 9 |
| 5 | `onvif_ws_security_usernametoken` | 正 | §3.4：UsernameToken 结构/命名空间/nonce+created | 9 |
| 6 | `onvif_soap12_envelope_structure` | 正 | §3.1/§3.2：envelope 编码规则与 Content-Type | 9 |
| 7 | `onvif_http_401_digest_challenge` | 正 | §3.1/§3.4/§4②：401 挑战→带凭据重请求→200 | 11 |
| 8 | `onvif_ws_addressing_correlation` | 正 | §3.3：Action/MessageID/RelatesTo 逐项与配对 | 9 |
| 9 | `onvif_media_get_profiles` | 正 | §3.5/§4③：GetProfiles 与 profile token | 9 |
| 10 | `onvif_media_get_stream_uri` | 正 | §3.5/§4③：GetStreamUri、token 关联、MediaUri 返回字段 | 11 |
| 11 | `onvif_media_get_snapshot_uri` | 正 | §3.5：GetSnapshotUri | 9 |
| 12 | `onvif_ptz_continuous_move_stop` | 正 | §3.5/§4④：PTZ ver20 命名空间、Move→Stop 顺序 | 11 |
| 13 | `onvif_events_create_pullpoint_subscription` | 正 | §3.5/§4⑤：订阅建立、SubscriptionReference | 9 |
| 14 | `onvif_events_pull_messages` | 正 | §3.5/§4⑤：PullMessages、wsa:To、NotificationMessage | 9 |
| 15 | `onvif_soap_fault_response` | 正 | §3.4/§3.6/§4⑥：认证缺失 Fault、HTTP 400、ter:NotAuthorized | 9 |
| 16 | `onvif_http_keepalive_multi_transaction` | 正 | §5/§4①：同连接多事务严格交替 | 13 |
| 17 | `onvif_ipv6_transport` | 正 | §2/§8：IPv6 独立 fixture | 9 |
| 18 | `onvif_multi_session` | 正 | §8/§5：多会话双四元组、状态不串用 | 18 |
| 19 | `onvif_mss_large_capabilities` | 正 | §3.7/§8：大响应跨 MSS 分段重组 | ≥11 校准 |
| 20 | `onvif_long_profile_token` | 正 | §8：长 ProfileToken/MessageID 边界 | 9 |
| 21 | `onvif_capabilities_no_such_service_fault` | 正 | §3.6/§3.1/§4⑥：HTTP 500 通用 Fault、GetCapabilities NoSuchService | 9 |
| 22 | `onvif_neg_soap_envelope` | 负 | §7：envelope 命名空间/XML 结构错 | — |
| 23 | `onvif_neg_content_type` | 负 | §7：Content-Type 错 | — |
| 24 | `onvif_neg_action` | 负 | §7：action 与操作不一致 | — |
| 25 | `onvif_neg_addressing` | 负 | §7：wsa 关联错 | — |
| 26 | `onvif_neg_unknown_operation` | 负 | §7：未知操作/服务不匹配 | — |
| 27 | `onvif_neg_parameter` | 负 | §7：缺必选参数 | — |
| 28 | `onvif_neg_auth` | 负 | §7：认证缺失/字段不全 | — |
| 29 | `onvif_neg_carrier_port` | 负 | §7：载体/端口/层链错 | — |
| 30 | `onvif_neg_fault_structure` | 负 | §7：Fault 结构错 | — |
| 31 | `onvif_neg_length_truncation` | 负 | §7：截断/长度不符 | — |
| 32 | `onvif_neg_subscription_correlation` | 负 | §7：订阅关联错 | — |
| — | `onvif_neg_unregistered` | 占位 | 当前层注册前置 | — |

## 3. 线上编码和偏移断言

层链 `[tcp, http, onvif]`，无 VLAN/IP options/TCP options 时 HTTP 起行 IPv4 offset 54、IPv6 offset 74。**SOAP envelope 在 HTTP body 内，偏移不固定**：body 起点 = 54/74 + 该 fixture 固定 HTTP 头集合字节长 + 2（空行 CRLF；头集合由配置钉死，偏移可预算）。断言分层：

1. **HTTP 起行与头（fields 权威断言）**：请求帧 offset 54 起为 ASCII `POST /onvif/device_service HTTP/1.1`（hex `50 4F 53 54 20 2F 6F 6E 76 69 66 2F 64 65 76 69 63 65 5F 73 65 72 76 69 63 65 20`）；字段断言用 `http.request.method=POST`、`http.request.uri.path`、`http.content_type` 以 `application/soap+xml` 开头且含 `charset=utf-8`、`http.content_length` 等于 `http.file_data` 实际字节长、`http.host` 为 dst_ip、`http.connection` 依事务数（多事务 `keep-alive`/末事务 `close`）。
2. **SOAP envelope（frames hex + http.file_data 双通道）**：`http.file_data` nonzero 证明 body 存在；envelope 结构用 body 起点偏移的稳定 ASCII 前缀断言：`3C 3F 78 6D 6C`（`<?xml`）、`3C 73 3A 45 6E 76 65 6C 6F 70 65`（`<s:Envelope`，前缀可配置但 fixture 钉死）、`77 77 77 2E 77 33 2E 6F 72 67 2F 32 30 30 33 2F 30 35 2F 73 6F 61 70 2D 65 6E 76 65 6C 6F 70 65`（envelope 命名空间 URI）、`77 77 77 2E 6F 6E 76 69 66 2E 6F 72 67 2F 76 65 72 31 30 2F 64 65 76 69 63 65 2F 77 73 64 6C`（device 命名空间）等。**TCP 分段边界不是 HTTP/SOAP 边界**：跨段时先按 `tcp.stream` 重组，再对重组后末帧断言完整 envelope 与 Content-Length。
3. **WS-Addressing/认证字段**：`wsa:MessageID`/`wsa:RelatesTo` 以 body 内 frames 字节断言（`3C 77 73 61 3A 4D 65 73 73 61 67 65 49 44`（`<wsa:MessageID`）、`3C 77 73 61 3A 52 65 6C 61 74 65 73 54 6F`（`<wsa:RelatesTo`））或 `http.file_data` 子串断言（实现期定）；401 挑战断言 `http.response.code=401` + `http.www_authenticate` 含 `Digest`；重发请求断言 `http.authorization` 含 `Digest`；UsernameToken 的 `3C 55 73 65 72 6E 61 6D 65 54 6F 6B 65 6E`（`<UsernameToken`）/`<Nonce`/`<Created` 存在、`Password Type="…#PasswordDigest"` 字节前缀。
4. **has_payload 语义**：SOAP 帧经常远大于普通帧，`frame.len>80` 只作宽松代理；**权威断言是 `http.file_data` nonzero + 上述 body 起点的 XML/envelope hex 前缀**，二者齐备才算"有 SOAP 载荷"，不得以包数或 PSH 标志替代。
5. **多会话包号规则**：`sessions[]` 按多会话展开整块回放——先跑完第 1 个会话全流程（握手→事务→挥手）再跑第 2 个，不交错；**第二会话 TCP 握手包号 = 前一会话总包数 + 1**。断言跨会话关联（MessageID/订阅引用）时用 `tcp.stream` 区分，不硬编码全局包号。

## 4. 正例逐项断言契约

约定 packet_count 见 §2 表；以下 fields/frames 为最低断言集，实现期可增不可减。默认 fixture 地址 `192.0.2.67 → 198.51.100.67`、`dst_port=80`、服务路径 `/onvif/device_service`、`/onvif/media_service`、`/onvif/event_service`、`/onvif/ptz_service`；envelope 命名空间 `http://www.w3.org/2003/05/soap-envelope`；wsa 命名空间 `http://www.w3.org/2005/08/addressing`（各用例以固定前缀 `s:`/`wsa:` 渲染，断言与渲染器输出一致——fixture 钉死前缀与命名空间 URI）。`relates_to same_as 请求 MessageID` 指同 `tcp.stream` 内响应帧 `http.file_data` 中 `<wsa:RelatesTo>` 文本等于请求帧 `<wsa:MessageID>` 文本——实现期以 case JSON 支持的断言语义落地。

1. **`onvif_ipv4_get_system_date_and_time`**（9）：握手；请求帧 `http.request.method=POST`、`http.request.uri.path=/onvif/device_service`、`http.content_type` 含 `application/soap+xml` 与 `charset=utf-8`、`http.file_data` nonzero + 帧 body 起点 `<?xml` hex、`<s:Envelope` hex、envelope 命名空间 URI hex、`<tds:GetSystemDateAndTime` hex、`<wsa:Action>` 含 `GetSystemDateAndTime`、`<wsa:MessageID` 存在（nonzero/fixture 固定时精确）；响应帧 `http.response.code=200`、`http.file_data` nonzero、`<tds:GetSystemDateAndTimeResponse` hex、`<tds:UTCDateTime` 存在（Core Spec §8.3.6 设备必须提供）、`<wsa:RelatesTo` 文本与请求 MessageID 一致；挥手。该操作 PRE_AUTH——请求**无** `Security`/`Authorization` 头（无 `http.authorization`）。
2. **`onvif_device_get_capabilities`**（9）：请求含 `<tds:GetCapabilities>` + `<tds:Category>All</tds:Category>` 参数；响应 `http.response.code=200`、`<tds:GetCapabilitiesResponse` hex、`<tds:Capabilities` hex、各服务 `XAddr` 存在（Media/Events/PTZ 各一，URI 前缀 http：fixture 钉死地址 `http://198.51.100.67/onvif/media_service` 等）；`wsa:RelatesTo` 关联同用例 1；PRE_AUTH 无凭据。
3. **`onvif_device_get_device_information`**（9）：请求带 UsernameToken（`<UsernameToken`/`<Username`/`<Password Type="…#PasswordDigest"`/`<Nonce`/`<Created` hex 存在，见用例 5）；响应 `http.response.code=200`、`<tds:GetDeviceInformationResponse` hex、五个字段元素 `Manufacturer`/`Model`/`FirmwareVersion`/`SerialNumber`/`HardwareId` 均存在且有序，值为 fixture 预配置（`Example`/`IPC-67`/`1.0.0`/`SN0000067`/`HW-67`，帧字节 ASCII 断言）；RelatesTo 关联。
4. **`onvif_device_get_network_interfaces`**（9）：请求带 UsernameToken；响应 `<tds:GetNetworkInterfacesResponse` hex、`<tt:NetworkInterfaces` hex、至少一个网络接口元素存在（`<tt:InterfaceToken` hex）；RelatesTo 关联。
5. **`onvif_ws_security_usernametoken`**（9）：单笔带认证事务（如 GetDeviceInformation）。断言：`http.file_data` 含 `xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"` 的 secext 命名空间 URI hex、`<UsernameToken`、`<Username`（admin）、`<Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"`、`<Nonce` + `EncodingType="…#Base64Binary"`、`<Created` 且全为 **nonce 与 created 并存**（设计 §3.4 强制）；Password/Nonce 值为 base64 不透明字节（`http.file_data` 子串某 base64 形态，实现期以渲染器预配置或 nonzero 断言）；**不验证摘要正确性**（核心规范无密钥场景不声称认证成功）。
6. **`onvif_soap12_envelope_structure`**（9）：单笔 PRE_AUTH 事务（GetSystemDateAndTime）。逐项断言：`<?xml version="1.0" encoding="UTF-8"?>` 声明字节前缀；`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"`（envelope URI hex，前缀 fixture 钉死）；`<s:Header>` 在 `<s:Body>` 之前（body 内字节序断言 Header 闭合在 Body 开前）；`<s:Body>` 存在且含单个操作元素；操作元素前缀与命名空间对应（`<tds:`）；`http.content_type` 恰为 `application/soap+xml; charset=utf-8`；SOAPAction 头**不出现**（请求行/头断言无 `SOAPAction:` 行——SOAP 1.2 语义，设计 §3.1）；body **不含 SOAP encoding 命名空间**（`http://schemas.xmlsoap.org/soap/encoding/` 子串不出现——document/literal 无 SOAP encoding，设计 §3.2）。
7. **`onvif_http_401_digest_challenge`**（11）：三帧序列（两事务）：事务 1 请求（GetDeviceInformation，**无** `auth` 声明/无凭据）→ 响应 `http.response.code=401` + `http.www_authenticate` 含 `Digest`（含 `realm=`/`nonce=`/`qop=auth`，frames 字节断言）；事务 2 请求携带 `http.authorization` 含 `Digest`（设计 §5：重发由事件序列显式声明，引擎不自动补）→ 响应 `http.response.code=200` + `GetDeviceInformationResponse`；请求/响应严格交替。
8. **`onvif_ws_addressing_correlation`**（9）：单笔事务（GetSystemDateAndTime）。断言：请求 `<wsa:Action>` 文本恰为 `http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime`（frames 字节）；`<wsa:MessageID` 存在、以 `urn:uuid:` 开头（fixture 固定时精确断言完整值）；响应 `<wsa:Action>` 文本 = 请求 Action 尾段 `GetSystemDateAndTime` → `GetSystemDateAndTimeResponse` 形态；响应 `<wsa:RelatesTo` 文本 = 请求 MessageID 值（`same_as` 关联）；`wsa:` 前缀命名空间 URI 为 `http://www.w3.org/2005/08/addressing`（hex 断言）。
9. **`onvif_media_get_profiles`**（9）：请求 `http.request.uri.path=/onvif/media_service`、`<trt:GetProfiles` hex、`<wsa:Action>` 含 `http://www.onvif.org/ver10/media/wsdl/GetProfiles`；响应 `<trt:GetProfilesResponse` hex、`<trt:Profiles` + 至少一个 `<trt:Profile token="profile_1">`（token 属性 fixture 预配置）、`<tt:VideoEncoderConfiguration` 子结构存在（fixture 预配置 H264/1920x1080）；RelatesTo 关联。
10. **`onvif_media_get_stream_uri`**（11）：两事务。事务 1 同用例 9（GetProfiles，返回 `profile_1`）；事务 2 GetStreamUri：请求含 `<trt:StreamSetup><trt:Stream>RTP_Unicast</trt:Stream></trt:StreamSetup>`（WSDL 必选，设计 §3.5）+ `<trt:ProfileToken>profile_1</trt:ProfileToken>`——**ProfileToken 值 = 事务 1 响应 Profiles[0] 的 token**（`same_as_packet`/`same_as_response` 关联断言）；响应 `<trt:GetStreamUriResponse` + `<trt:MediaUri><tt:Uri>rtsp://198.51.100.67:554/profile_1/stream1</tt:Uri>`——**仅断言 URI 存在/前缀 `rtsp://` 与 fixture 文本**，不派生 RTP 数据面（设计 §3.5 流关联边界，本用例包尾即挥手，无后续媒体帧——以 packet_count=11 与末帧 FIN 断言之）。
11. **`onvif_media_get_snapshot_uri`**（9）：请求 `<trt:GetSnapshotUri` + `<trt:ProfileToken>profile_1</trt:ProfileToken>`（fixture 直给，单事务）；响应 `<trt:MediaUri><tt:Uri>` 为 `http://198.51.100.67/onvif/snapshot/profile_1`（HTTP 形态快照 URL）；仅返回字段断言。
12. **`onvif_ptz_continuous_move_stop`**（11）：两事务（Move 先于 Stop，事件编排顺序）。事务 1 `http.request.uri.path=/onvif/ptz_service`、请求 `<tptz:ContinuousMove` + `<tptz:ProfileToken>` + `<tptz:Velocity>`（含 `<tt:PanTilt>` x/y）；**命名空间 URI 为 `http://www.onvif.org/ver20/ptz/wsdl`**（hex 断言，设计 §3.5 实测）；响应 `<tptz:ContinuousMoveResponse`（空 body 元素，合法）。事务 2 `<tptz:Stop` + ProfileToken、响应 `<tptz:StopResponse`；两事务 MessageID distinct、RelatesTo 各自配对；Move 帧在 Stop 帧之前（包序断言）。
13. **`onvif_events_create_pullpoint_subscription`**（9）：请求 `http.request.uri.path=/onvif/event_service`、`<tev:CreatePullPointSubscription` + `<tev:InitialTerminationTime>PT1M</tev:InitialTerminationTime>`（duration 形态）；`<wsa:Action>` 含 `http://www.onvif.org/ver10/events/wsdl/EventPortType/CreatePullPointSubscriptionRequest`（Core Spec §9.10.3 原文形态，frames 字节）；响应 `<tev:CreatePullPointSubscriptionResponse` hex、`<tev:SubscriptionReference><wsa:Address>` 存在（订阅端点 URL：fixture 预配置 `http://198.51.100.67/onvif/subscription?Idx=0`）、`<wsnt:CurrentTime`/`<wsnt:TerminationTime` 存在且为 UTC（`Z` 指示，§9.1.1 原文）——日期时间值动态，nonzero/presence 断言。
14. **`onvif_events_pull_messages`**（9）：请求 `<tev:PullMessages>` + `<tev:Timeout>PT5S</tev:Timeout>` + `<tev:MessageLimit>2</tev:MessageLimit>`（WSDL 双必选，设计 §3.5）；`<wsa:To>` = 订阅端点地址（fixture 预配置与用例 13 响应同值，单事务内以 fixture 值断言）；`<wsa:Action>` 含 `PullPointSubscription/PullMessagesRequest`（§9.10.5 原文形态）；响应 `<tev:PullMessagesResponse` hex、`<tev:CurrentTime`/`<tev:TerminationTime` 存在、`<wsnt:NotificationMessage` 存在（含 `<wsnt:Topic Dialect="…#ConcreteSet">` 与 `<tt:SimpleItem Name=… Value=…>`，fixture 预配置一条告警）；RelatesTo 关联。超时零消息形态（NotificationMessage 为空）由数据场景边界声明，此处正例带一条消息。
15. **`onvif_soap_fault_response`**（9）：请求 GetDeviceInformation（**无凭据**，fixture 声明设备**仅支持 UsernameToken 认证模式**、digest 挑战不可用——§5.9.1 认证路径，设计 §3.4/§3.6）；响应 **`http.response.code=400`**（认证缺失 Fault 状态码，§5.9.1；**非 500**——500 为通用 Fault 形态，由用例 21 单独覆盖，两形态不混用）、`http.file_data` 含 `<s:Fault` hex、`<s:Code><s:Value>env:Sender</s:Value>`、`<s:Subcode><s:Value>ter:NotAuthorized</s:Value>`（ter 命名空间 URI `http://www.onvif.org/ver10/error` hex，Table 4）、`<s:Reason><s:Text xml:lang="en">Sender not Authorized</s:Text>`；Fault 的 `<wsa:Action>` 为 `http://www.w3.org/2005/08/addressing/soap/fault`（§9.9）；RelatesTo 关联。**Fault 响应是合法协议事件（正例），非 planner error**。
16. **`onvif_http_keepalive_multi_transaction`**（13 = 3+6+4，3 事务）：单 `tcp.stream` 承载 GetSystemDateAndTime→GetCapabilities→GetProfiles 三笔事务；断言请求/响应**严格交替**（`http.request` 与 `http.response` 帧序 1:1，无 pipelining）、各事务 MessageID distinct（fixture 固定三个 uuid 时精确断言）、各响应 RelatesTo 与本请求 MessageID 配对、各请求均带 `http.connection=keep-alive`、**仅末事务**请求为 `close`（设计 §3.1）、每帧 `http.file_data` 长度与 `http.content_length` 自洽；末响应后挥手。
17. **`onvif_ipv6_transport`**（9）：IPv6 独立 fixture（`2001:db8::67 → 2001:db8::100:67`，显式给出，不从 IPv4 推导）；断言 `ipv6.nxt=6`（TCP）、HTTP 起行 offset 74、POST/GetSystemDateAndTime 形状与用例 1 相同、envelope 骨架字节与用例 1 一致（仅外层 IP 头不同）、RelatesTo 关联；**不得**出现 `ip.version=4` 地址。
18. **`onvif_multi_session`**（18 = 9+9）：会话 1（`src_port=4067`，GetSystemDateAndTime + GetDeviceInformation 两事务，或单事务基线 9 包）与会话 2（`src_port=4068`，GetProfiles 单事务）；断言两 `tcp.stream` distinct、MessageID 各会话独立（distinct_values 两会话各一）、第二会话握手包号 = 10（多会话展开起点 = 前会话总包数 + 1）、各会话响应 RelatesTo 匹配本会话请求（无串用）、会话 1 订阅/引用内容不泄漏进会话 2（fixture 断言）。
19. **`onvif_mss_large_capabilities`**（≥11 校准）：GetCapabilities 响应含全部服务 XAddr 与多能力条目（fixture 配置 ≥1500 字节 envelope），MSS 压小使响应跨 ≥2 个 TCP 分段；断言 `tcp.len` 分布≥2 段、按 `tcp.stream` 重组后末帧 `http.file_data` 完整（`http.content_length` 与重组后 body 字节数一致、`Capabilities` 闭合标签存在、`XAddr` 计数与配置一致）、分段边界不切 SOAP 元素（重组前任何单段不得含完整 `</s:Envelope>`——frames 断言；**该断言以 fixture MSS 校准切分位置成立——若 MSS 取值使完整闭合标签恰好落入单一分段，则降级为仅"重组后 envelope 完整"单断言**，实现期以实际分段输出校准）。
20. **`onvif_long_profile_token`**（9）：GetStreamUri 使用长 ProfileToken（fixture 64 字符 `tok_` + 60 hex）与较长 MessageID（完整 `urn:uuid:` 36 字符，fixture 钉死）；断言请求 `<trt:ProfileToken>` 文本 = 长 token 完整值（帧字节 ASCII 精确）、响应 `MediaUri` 含该 token 子串、MessageID 完整出现且 RelatesTo 同值回带（长值跨段时按 `tcp.stream` 重组后断言——单段内装不下时按用例 19 规则处理，实现期校准 packet_count）。
21. **`onvif_capabilities_no_such_service_fault`**（9）：请求 GetCapabilities 携带设备**不支持的能力类别**（fixture 预配置，如设备未实现 Analytics 服务而请求 `<tds:Category>Analytics</tds:Category>`——设计 §3.6 GetCapabilities 特有 Fault，§8.1.2.4）；响应 **`http.response.code=500`**（§5.8.2.1/§9.9 通用 Fault 状态码，与用例 15 的 400 认证路径区分）、`http.file_data` 含 `<s:Fault` hex、`<s:Code><s:Value>env:Receiver</s:Value>`、`<s:Subcode><s:Value>ter:ActionNotSupported</s:Value>` 及嵌套子码 `ter:NoSuchService`（子码组合与 Reason 文本实现期对 Core Spec §8.1.2.4 核实，设计 §3.6 注；Reason 文本 fixture 钉死）、`<s:Reason><s:Text xml:lang="en">` 存在；Fault 的 `<wsa:Action>` 为 `http://www.w3.org/2005/08/addressing/soap/fault`（§9.9）；RelatesTo 关联。本例同时为设计 §3.1 Table 5"HTTP 500 承载 Fault"合法事件的正例断言（与 §7"不得误报"注呼应）。
22. **`onvif_neg_soap_envelope`**（负）：`wire_fault` 注入 XML 截断（envelope 未闭合）、envelope 命名空间写为 SOAP 1.1 (`http://schemas.xmlsoap.org/soap/envelope/`)、Body 缺失、Header 在 Body 之后；锚词（error_contains 字面值）见 §5。
23. **`onvif_neg_content_type`**（负）：`wire_fault` 注入 Content-Type `text/xml`（无 soap+xml）或缺 `charset=utf-8`；锚词见 §5。
24. **`onvif_neg_action`**（负）：Content-Type `action` 参数或事件声明的 wsa:Action 与 body 操作不一致（如 action 声明 GetCapabilities 而 body 是 GetProfiles）；锚词见 §5。
25. **`onvif_neg_addressing`**（负）：请求缺 `wsa:MessageID`/`wsa:Action`、响应声明缺 `wsa:RelatesTo` 或 RelatesTo ≠ 请求 MessageID、wsa 命名空间错误；锚词见 §5。
26. **`onvif_neg_unknown_operation`**（负）：未知操作名（如 `GetFooBar`）、media 操作放在 device 命名空间（服务/命名空间不匹配）；锚词见 §5。
27. **`onvif_neg_parameter`**（负）：GetStreamUri 缺 StreamSetup 或缺 ProfileToken、PullMessages 缺 Timeout 或缺 MessageLimit、参数类型错误（Timeout 非 duration 文本）；锚词见 §5。
28. **`onvif_neg_auth`**（负）：需认证事务（READ_SYSTEM+）无 `auth` 声明且无 401 往返声明（缺少凭据路径）、UsernameToken 缺 Nonce 或缺 Created；锚词见 §5。
29. **`onvif_neg_carrier_port`**（负）：层链缺 http（`[tcp, onvif]` 直连）、端口/载体矛盾、WS-Discovery UDP 载体误配为主链；锚词见 §5。
30. **`onvif_neg_fault_structure`**（负）：Fault 响应缺 `Code` 或缺 `Reason`、`Code/Value` 不在 SOAP 1.2 值域、Subcode 缺 ter 命名空间（裸 `NotAuthorized` 无前缀/无 namespace 声明）；锚词见 §5。
31. **`onvif_neg_length_truncation`**（负）：envelope 渲染截断（闭合标签缺失致字节数与声明不符）、Content-Length ≠ 渲染字节数；锚词见 §5。
32. **`onvif_neg_subscription_correlation`**（负）：PullMessages 的 `wsa:To`/订阅引用 `same_as_response` 指向非 CreatePullPointSubscription 事件或不存在的事件、跨会话引用订阅；锚词见 §5。

**正例总则**：每条实现后至少含 `packet_count`/`min_packets`、载体与方向断言、`has_payload`（`http.file_data` nonzero + envelope hex 前缀）、可观察 fields（`http.*` 实测字段）、稳定 frames（body 起点 EV 前缀与关键 token 字节）；动态值（MessageID/Nonce/时间）只用存在与关联断言。合法 I 类事件（HTTP 401/400/405/415、SOAP Fault、PullMessages 超时零消息、PRE_AUTH 免认证）均为正例形态，只有配置、线格式、状态、关联、长度错误进入负例（设计 §7）。

## 5. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP/HTTP 外壳的假成功；执行期 `expect` 严格只有 `expect_error`、`error_contains`。锚词与设计 §7 表一一对应：

| ID | 故障输入（`wire_fault`/配置注入口） | 目标 `error_contains` |
|---|---|---|
| `onvif_neg_soap_envelope` | XML 截断/envelope 命名空间错（含 SOAP 1.1）/Body 缺失/Header 顺序颠倒 | `soap`、`envelope` 或 `xml` |
| `onvif_neg_content_type` | Content-Type 非 application/soap+xml、缺 charset=utf-8 | `content-type`、`media` 或 `charset` |
| `onvif_neg_action` | Content-Type action 参数与操作不一致、声明的 action 与服务/操作不匹配 | `action` 或 `soapaction` |
| `onvif_neg_addressing` | 缺 wsa:Action/MessageID、响应缺 RelatesTo 或 RelatesTo ≠ 请求 MessageID、wsa 命名空间错 | `addressing`、`relates` 或 `message` |
| `onvif_neg_unknown_operation` | 未知操作/操作与服务命名空间不匹配 | `operation`、`service` 或 `namespace` |
| `onvif_neg_parameter` | GetStreamUri 缺 StreamSetup/ProfileToken、PullMessages 缺 Timeout/MessageLimit、参数类型错 | `parameter`、`argument` 或 `missing` |
| `onvif_neg_auth` | 需认证事务无 auth 且无 401 往返、UsernameToken 缺 Nonce/Created | `auth`、`security` 或 `token` |
| `onvif_neg_carrier_port` | 层链缺 http、端口/载体矛盾、WS-Discovery 误配 | `carrier`、`port` 或 `layer` |
| `onvif_neg_fault_structure` | Fault 缺 Code/Reason、Code/Value 值域外、Subcode 缺 ter 命名空间 | `fault`、`code` 或 `reason` |
| `onvif_neg_length_truncation` | envelope 截断、Content-Length ≠ 渲染字节数 | `length`、`truncat` 或 `content-length` |
| `onvif_neg_subscription_correlation` | PullMessages wsa:To 无来源/跨会话引用订阅 | `subscription`、`correlation` 或 `reference` |

合法协议事件不进负例（防误报）：HTTP 401 挑战本身、HTTP 400/405/415、SOAP Fault 响应本身（Table 4 全子码）、PullMessages 超时零消息、GetCapabilities `ter:NoSuchService`、PRE_AUTH 免认证、MessageID 跨会话独立重复。

## 6. 五层覆盖映射

| 层面 | 用例 ID | 说明 |
|---|---|---|
| 功能 | 1–16、21（正）；22–32（负） | 四服务 11 操作各自正例 + envelope/action/addressing/auth/Fault 编码规则 + 401 挑战 + 多事务；负例 11 类锚词逐类（设计 §7 每行对应 ≥1 条）；多流显式不适用（HTTP/1.1 无 pipelining，设计 §4 声明） |
| 性能 | 19、20 | 大 GetCapabilities 响应跨 MSS 分段重组；长 token/MessageID 跨段与上界；发包速率由框架既有配置承载（v1.1 §10 口径） |
| 数据场景 | 1、5、13、14、20；负 27、30 | 值域与编码变体：PRE_AUTH vs READ_SYSTEM 访问类别边界、duration/int/dateTime 参数类型、base64 不透明（Nonce/Password）、空 NotificationMessage 列表、Fault 值域；必选参数缺失拒绝 |
| 地址与流 | 1（v4 单流基线）、17（v6）、18（多会话双四元组） | v4+v6 必覆盖；流关联显式不适用（媒体 URI 仅返回字段不派生 RTSP 数据面，设计 §3.5 声明）；单流基线（1） |
| 业务 | 1/2（接入首链）、3/4（认证读信息）、9/10/11（取流准备）、12（PTZ）、13/14（事件轮询）、7（401 认证）、16（长连接多操作）、15/21（设备错误路径） | 现网客户端接入日常场景优先 |

## 7. 机器契约与静态检查

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/onvif.json` 通过；当前数组恰含 1 条 `onvif_neg_unregistered`：`proto=onvif`、层链 `[{"tcp":{}},{"http":{}},{"onvif":{}}]`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。
2. 实现注册 `onvif` 层后：移除占位，按 §2 顺序补入 32 个语义用例；ID、顺序与设计 §9 完全一致（脚本核验）。
3. 正例每条含 `packet_count`（或 `min_packets`）+ `fields` + `frames`；`fields` 只用 §1 实测存在的 tshark 字段，**不伪造 `onvif.*`/`soap.*`/`wsa.*`**；SOAP 断言用 §3 的 body 起点 hex 前缀约定（`http.file_data` + frames 双通道）。
4. 负例 `expect` 键集合恰为 `{expect_error, error_contains}`，不加 packet_count/fields。
5. 断言包号引用跨会话/跨连接时用 `tcp.stream`+会话起点规则（§3.5），不硬编码全局包号；动态值用 `same_as_packet`/`distinct_values`/`nonzero`。
6. 若实现期实证 tshark 对 `application/soap+xml` 自动内层 XML 解码（`xml.tag` 可用），四件套同步更新；未实证前不得把 `xml.*` 写进最低断言集。

## 8. 三方一致性表

设计 §9、本文 §2、实现后 `onvif.json` 保持同一 32 个语义 ID、同一顺序（当前 JSON 另有占位，不计入）：

```text
onvif_ipv4_get_system_date_and_time
onvif_device_get_capabilities
onvif_device_get_device_information
onvif_device_get_network_interfaces
onvif_ws_security_usernametoken
onvif_soap12_envelope_structure
onvif_http_401_digest_challenge
onvif_ws_addressing_correlation
onvif_media_get_profiles
onvif_media_get_stream_uri
onvif_media_get_snapshot_uri
onvif_ptz_continuous_move_stop
onvif_events_create_pullpoint_subscription
onvif_events_pull_messages
onvif_soap_fault_response
onvif_http_keepalive_multi_transaction
onvif_ipv6_transport
onvif_multi_session
onvif_mss_large_capabilities
onvif_long_profile_token
onvif_capabilities_no_such_service_fault
onvif_neg_soap_envelope
onvif_neg_content_type
onvif_neg_action
onvif_neg_addressing
onvif_neg_unknown_operation
onvif_neg_parameter
onvif_neg_auth
onvif_neg_carrier_port
onvif_neg_fault_structure
onvif_neg_length_truncation
onvif_neg_subscription_correlation
```

## 9. 修订记录

- v1.0.0（2026-08-20）：旧稿首版（与旧设计稿配套的 14+6 ID 索引，含 discovery_probe/tls/pcap_nic 等）。
- v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写，取代 2026-08-20 旧稿（旧稿见 git 历史）。索引表改为需求五列格式（覆盖列引用设计 § 编号）；以 tshark 3.6.14 `-G fields`/`-G protocols` 实测固化"无 `onvif.*`/`soap.*`/`wsa.*` 字段、fields 只用 `http.*`/`tcp.*`/`ipv6.nxt`、SOAP 走 body 起点 frames hex 前缀 + `http.file_data` 双通道"的断言基线（与 64-cwmp 同款，XML 通用 dissector 未实证前不用）；用例按原子原则重排为 31 条（20 正 + 11 负）——每服务每操作各一例、envelope/action/addressing/auth/Fault 编码规则各一例、401 挑战、多事务 keep-alive、多会话、MSS 大响应、长 token 边界各一例，负例 11 类锚词逐条与设计 §7 对齐；新增 §3 偏移与双通道断言、§6 五层映射、§8 三方一致性表；删除 discovery/tls/pcap_nic（本版边界，见设计 §1）。
- v2.0.1（2026-09-01）：按独立隔离审查 9 项问题清单修复（2 MAJOR / 5 MINOR / 2 待核验注）：**O02**（MAJOR）用例 15 改回 HTTP 400 认证 Fault 断言（GetDeviceInformation 无凭据 + 仅 UsernameToken 模式，§5.9.1 认证路径），HTTP 500 通用 Fault 另起新用例 21 `onvif_capabilities_no_such_service_fault`（GetCapabilities 不支持类别 → `env:Receiver/ter:ActionNotSupported/ter:NoSuchService`，同时补上 O03 的正例缺口），总数 31→32（21 正 + 11 负）、负例重排 22–32，索引表/五层映射/§8 三方一致性表同步；**O05** 用例 6 补"body 不含 SOAP encoding 命名空间（`http://schemas.xmlsoap.org/soap/encoding/` 子串不出现）"断言；**O06** 用例 19"重组前单段不含完整 `</s:Envelope>`"断言注明以 fixture MSS 校准切分位置、不满足时降级为"重组后 envelope 完整"单断言；**O07** 用例 16 keep-alive 口径改为"各请求 `keep-alive`、仅末事务 `close`"（对齐设计 §3.1）。复验轮设计文档 2 项 MINOR（R1 状态码统计、R2 400 语义消歧）同步修复，复验确认 clean。
