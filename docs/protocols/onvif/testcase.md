# ONVIF（网络视频接口论坛，Open Network Video Interface Forum）测试用例契约

> 版本：v2.1.1（测试用例）
> 日期：2026-09-01
> 配套设计：`docs/protocols/onvif/design.md`（v2.1.1）
> 机器契约：`trafficgen/test/protocol_pcap/cases/onvif.json`（proto key：`onvif`；当前为 **95 条语义用例 + 1 条 presence 负例**；95 条语义用例的 `spec_json` 已迁入层链，presence 负例故意保留顶层 `onvif` 旁路键以验证拒绝）
> 状态：按《协议设计文档与用例文档需求文档 v1.3》完成独立重审（审查员 rr-onvif：行为面 138 点、confirmed findings 24 项），本版为修复轮产物：32 条 → **95 条（57 正 + 38 负）**；v2.1.1 复验已 clean。95 条语义用例已完成层链唯一配置迁移，presence 负例保留为旧键拒绝守卫。记录见 §9。
> 修订记录：v2.1.0（2026-09-01）：按 v1.3 行为面全枚举重出并修复 rr-onvif 24 项 finding（2C/10M/12M，详见 §9）；v2.0.1/v2.0.0（2026-09-01）：v1.1 隔离审查轮（见 §9 历史条目）。

## 1. 测试原则和当前注册边界

用例按《需求文档 v1.3》从规范（ONVIF Core Spec Ver. 26.06 + 四份 WSDL + SOAP 1.2/WS-Addressing/WSS/WS-BaseNotification）与设计 §2–§8 派生：**可测试行为面全枚举**（消息 × 字段 × 值域 × 边界 × 错误分支 × 载体 × 场景 × 交互），用例 = 不可再分的测试点，数量由行为面决定（本版 95 条 = 57 正 + 38 负，对应 rr-onvif 枚举的 138 行为面点）。依据列标注出处（规范优先）；不要求与设计章节一对一映射。**pcap 与 port_group/NIC 两种输出路径使用同一份用例契约**（同一 ID、同一断言、同一包数，与 64-cwmp/66-doh 同形）。

当前 JSON 的 95 条语义用例均采用严格层链配置：地址在 `layers.ip`，端口在 `layers.tcp`，业务配置在 `layers.onvif`；另保留 1 条 `onvif_neg_presence_top_level_onvif`，故意同时放置顶层 `onvif` 与层内配置，验证旧键被拒绝。presence 负例不计入 95 条语义行为面。

**TSHARK 实测基线（本机 3.6.14，`-G fields`/`-G protocols` 核验，非臆造）**：本机**没有 ONVIF/WS-\* 专用 dissector（解析器）**，不存在任何 `onvif.*`、`soap.*`、`wsa.*` 字段，**不得臆造**。可用字段：`http.request.method`、`http.request.uri`、`http.request.uri.path`、`http.request.line`、`http.response.code`、`http.response.line`、`http.content_type`、`http.content_length`、`http.content_length_header`、`http.file_data`（FT_STRING，body 原始字节）、`http.host`、`http.connection`、`http.authorization`、`http.www_authenticate`、`tcp.stream`、`tcp.len`、`tcp.dstport`、`tcp.flags.*`、`ip.version`、`ipv6.nxt`。SOAP/XML 内容断言走两条路：① `http.file_data` 存在性（fields nonzero）；② raw frame（原始帧）body 起点稳定 ASCII 前缀与关键字节的 hex 断言（`frames` 的 `offset/hex`，见 §3）。XML 通用 dissector（`xml.tag`）存在但对 `application/soap+xml` 的自动内层解码**未实证**——未实证前不把 `xml.*` 写进最低断言集。

**动态字段禁止硬编码**：`wsa:MessageID`（`urn:uuid:` 形态）、Nonce、Created/CurrentTime/TerminationTime（dateTime）、digest 摘要、订阅地址用 `nonzero`、`distinct_values`、`same_as_packet`/`same_as_response` 或帧字节前缀断言；fixture 显式固定 MessageID 的用例允许精确断言（§4 各例声明）。不声称设备真实身份/能力值/认证成功/签名有效/媒体流可播放。

**包数约定**（实现期校准值，非 RFC 消息数）：单事务（1 请求 + 1 响应，各单段）= 3（握手）+ 2（请求/响应）+ 4（挥手）= **9**；两事务 = 3+2×2+4 = **11**；三事务 = **13**；多会话/并发 = 各会话之和，第二会话握手包号 = 前会话总包数 + 1；MSS 分段每加 1 段 +1。负例无 packet_count。

## 2. 原子用例索引

| # | ID | 类型 | 载体 | 覆盖（一句话） | 依据 | 包数 |
|---:|---|---|---|---|---|---:|
| 1 | `onvif_ipv4_get_system_date_and_time` | 正 | TCP/IPv4 | POST/IPv4 明文单流基线（PRE_AUTH 免认证、envelope/头全家） | Core Spec §5.8.2.1/§8.3.6+设计§3.1/§3.2 | 9 |
| 2 | `onvif_device_get_capabilities` | 正 | TCP/IPv4 | GetCapabilities：Category=All 参数 + Capabilities/XAddr 响应结构 | Core Spec §8.1.2.4+设计§3.5 | 9 |
| 3 | `onvif_device_get_device_information` | 正 | TCP/IPv4 | GetDeviceInformation：五必选字段响应 + UsernameToken | Core Spec §8.3.1+WSDL 实测 | 9 |
| 4 | `onvif_device_get_network_interfaces` | 正 | TCP/IPv4 | GetNetworkInterfaces：tds:NetworkInterfaces（token 属性）+ tt:Enabled（C-2 修正形状） | WSDL 实测（devicemgmt.wsdl 本地元素） | 9 |
| 5 | `onvif_network_interfaces_multi` | 正 | TCP/IPv4 | NetworkInterfaces 1..n 上界形态：双接口 token distinct | WSDL 实测（maxOccurs=unbounded） | 9 |
| 6 | `onvif_ws_security_usernametoken` | 正 | TCP/IPv4 | UsernameToken：secext 命名空间/四元素/nonce+created 并存 | Core Spec §5.9.5+WSS UsernameToken Profile | 9 |
| 7 | `onvif_usernametoken_created_namespace` | 正 | TCP/IPv4 | Created 元素的 utility 命名空间 URI 显式断言（D 组半→✓） | WSS utility ns+设计§3.4 | 9 |
| 8 | `onvif_soap12_envelope_structure` | 正 | TCP/IPv4 | envelope 编码规则全家：声明/命名空间/Header 先于 Body/无 SOAP encoding/无 SOAPAction 头 | SOAP 1.2 Part 1 §5+设计§3.2 | 9 |
| 9 | `onvif_soap12_prefix_variant` | 正 | TCP/IPv4 | XML 前缀任意判别：envelope 前缀 soapenv: + 同命名空间 URI（B 组✗→✓） | SOAP 1.2 Part 1 §5 前缀非标准原文 | 9 |
| 10 | `onvif_ws_addressing_correlation` | 正 | TCP/IPv4 | wsa:Action/MessageID/RelatesTo 逐项与配对 | WS-Addressing 1.0+NS §9.10 | 9 |
| 11 | `onvif_http_401_digest_challenge` | 正 | TCP/IPv4 | 401 挑战→带凭据重请求→200（三帧序列两事务） | Core Spec §5.9.1+设计§3.1 | 11 |
| 12 | `onvif_http_400_malformed_no_body` | 正 | TCP/IPv4 | Table 5 400 Malformed：无 envelope 错误响应（fixture 决策形态） | Core Spec §5.8.2.4 Table 5+设计§3.1 | 9 |
| 13 | `onvif_http_405_method_not_allowed` | 正 | TCP/IPv4 | Table 5 405：方法非 POST/GET 的合法错误响应（C-9） | Core Spec §5.8.2.4 Table 5 | 9 |
| 14 | `onvif_http_415_unsupported_media` | 正 | TCP/IPv4 | Table 5 415：不支持的封装媒体类型（C-9） | Core Spec §5.8.2.4 Table 5 | 9 |
| 15 | `onvif_http_host_explicit` | 正 | TCP/IPv4 | Host 显式域名（非 dst_ip 缺省） | 设计§3.1（doh #52 同形） | 9 |
| 16 | `onvif_single_transaction_connection_close` | 正 | TCP/IPv4 | 单事务会话 Connection 取值钉死 close（D-12） | 设计§3.1 v2.1 决策 | 9 |
| 17 | `onvif_port_nondefault` | 正 | TCP/IPv4 | 非默认端口 8080（C-7，端口变体） | 设计§2（cwmp #112/doh #22 同形） | 9 |
| 18 | `onvif_http_keepalive_multi_transaction` | 正 | TCP/IPv4 | 同连接 3 事务严格交替 + 逐请求 keep-alive/末笔 close | 设计§3.1/§5 | 13 |
| 19 | `onvif_media_get_profiles` | 正 | TCP/IPv4 | GetProfiles：trt:Profiles（token 属性）响应形状（C-1 修正） | WSDL 实测（media.wsdl 复数元素） | 9 |
| 20 | `onvif_media_get_profiles_multi` | 正 | TCP/IPv4 | GetProfiles 0..n 多实例：双 Profiles、token distinct | WSDL 实测 | 9 |
| 21 | `onvif_media_get_stream_uri` | 正 | TCP/IPv4 | GetStreamUri：StreamSetup+ProfileToken 必选、token←GetProfiles 事务交互、MediaUri 仅返回字段 | WSDL 实测+设计§3.5 流关联边界 | 11 |
| 22 | `onvif_media_get_snapshot_uri` | 正 | TCP/IPv4 | GetSnapshotUri：ProfileToken→MediaUri（http 形态快照 URL） | WSDL 实测 | 9 |
| 23 | `onvif_ptz_continuous_move` | 正 | TCP/IPv4 | ContinuousMove：ProfileToken+Velocity（tt:PTZSpeed，D-9 修正） | WSDL 实测（ptz.wsdl ver20） | 9 |
| 24 | `onvif_ptz_continuous_move_timeout` | 正 | TCP/IPv4 | ContinuousMove 可选 Timeout（xs:duration）携带形态（D-9/G 组） | WSDL 实测 | 9 |
| 25 | `onvif_ptz_move_stop_sequence` | 正 | TCP/IPv4 | PTZ Move→Stop 两事务顺序、ver20 命名空间、MessageID distinct | 设计§3.5/§4④ | 11 |
| 26 | `onvif_ptz_stop_no_flags` | 正 | TCP/IPv4 | Stop 双可选参数省略形态（G 组✗→✓） | WSDL 实测（PanTilt/Zoom minOccurs=0） | 9 |
| 27 | `onvif_ptz_stop_flags` | 正 | TCP/IPv4 | Stop 带 PanTilt=true Zoom=true 全参形态（G 组） | WSDL 实测 | 9 |
| 28 | `onvif_events_create_pullpoint_subscription` | 正 | TCP/IPv4 | CreatePullPointSubscription：PT1M + SubscriptionReference/CurrentTime/TerminationTime + 响应 Action 派生 | Core Spec §9.1.1/§9.10.3+WSDL 实测 | 9 |
| 29 | `onvif_events_create_with_filter` | 正 | TCP/IPv4 | Create 可选 Filter（wsnt:TopicExpression ConcreteSet dialect） | WS-BaseNotification+WSDL 实测 | 9 |
| 30 | `onvif_events_create_absolute_termination` | 正 | TCP/IPv4 | InitialTerminationTime 绝对时间形态（L 组） | WS-BaseNotification AbsoluteOrRelativeTimeType | 9 |
| 31 | `onvif_events_create_to_pull_correlation` | 正 | TCP/IPv4 | Create→Pull 两事务：Pull 的 wsa:To = Create 响应 SubscriptionReference（C-5 端到端） | Core Spec §9.10.5+设计§3.5 事务交互 | 11 |
| 32 | `onvif_events_pull_messages` | 正 | TCP/IPv4 | PullMessages：Timeout/MessageLimit 双必选 + NotificationMessage 载荷 + 响应 Action 派生 | Core Spec §9.1.2/§9.10.5+WSDL 实测 | 9 |
| 33 | `onvif_events_pull_messages_timeout_zero` | 正 | TCP/IPv4 | PullMessages 超时零消息合法形态（C-10） | Core Spec §9.1.2 原文 shall respond with zero messages | 9 |
| 34 | `onvif_events_pull_messages_limit_1` | 正 | TCP/IPv4 | MessageLimit=1 下界 | WSDL（xs:int） | 9 |
| 35 | `onvif_events_pull_messages_limit_int_max` | 正 | TCP/IPv4 | MessageLimit=2147483647 上界（xs:int 满值） | WSDL xs:int+设计§8 | 9 |
| 36 | `onvif_events_pull_timeout_pt0s` | 正 | TCP/IPv4 | Timeout=PT0S duration 零值边界 | xs:duration+设计§8 | 9 |
| 37 | `onvif_fault_400_auth` | 正 | TCP/IPv4 | 认证缺失 Fault：HTTP 400 + env:Sender/ter:NotAuthorized（§5.9.1 路径） | Core Spec §5.9.1/§5.8.2.2 Table 4 | 9 |
| 38 | `onvif_fault_500_no_such_service` | 正 | TCP/IPv4 | 500 通用 Fault：env:Receiver/ActionNotSupported/NoSuchService（§8.1.2.4） | Core Spec §8.1.2.4/§9.9 | 9 |
| 39 | `onvif_fault_full_form` | 正 | TCP/IPv4 | Fault 可选元素全形：Node/Role/Detail 携带（I 组） | SOAP 1.2 Part 1 §5.4+设计§3.6 | 9 |
| 40 | `onvif_capabilities_category_device` | 正 | TCP/IPv4 | CapabilityCategory 枚举 Device 单值（L 组 7 值枚举扩面） | Core Spec §8.1.2.4 | 9 |
| 41 | `onvif_capabilities_category_events` | 正 | TCP/IPv4 | CapabilityCategory 枚举 Events 单值 | Core Spec §8.1.2.4 | 9 |
| 42 | `onvif_capabilities_category_imaging` | 正 | TCP/IPv4 | CapabilityCategory 枚举 Imaging 单值 | Core Spec §8.1.2.4 | 9 |
| 43 | `onvif_capabilities_category_media` | 正 | TCP/IPv4 | CapabilityCategory 枚举 Media 单值 | Core Spec §8.1.2.4 | 9 |
| 44 | `onvif_capabilities_category_ptz` | 正 | TCP/IPv4 | CapabilityCategory 枚举 PTZ 单值 | Core Spec §8.1.2.4 | 9 |
| 45 | `onvif_capabilities_category_analytics` | 正 | TCP/IPv4 | CapabilityCategory 枚举 Analytics 单值（200 形态，与 #38 Fault 形态互补） | Core Spec §8.1.2.4 | 9 |
| 46 | `onvif_capabilities_multi_category` | 正 | TCP/IPv4 | Category 0..n 多值：单请求携带双类别 | WSDL 实测（maxOccurs=unbounded） | 9 |
| 47 | `onvif_date_time_daylight_timezone` | 正 | TCP/IPv4 | SystemDateAndTime：DaylightSavings=true + TimeZone 形态（D-10 拼写） | WSDL（tt:SystemDateTime） | 9 |
| 48 | `onvif_date_time_localtime` | 正 | TCP/IPv4 | SystemDateAndTime：LocalDateTime 存在形态 | WSDL+设计§3.5 | 9 |
| 49 | `onvif_date_time_manual` | 正 | TCP/IPv4 | DateTimeType=Manual（tt:SetDateTimeType 值域第二值） | WSDL（tt:SetDateTimeType 枚举） | 9 |
| 50 | `onvif_token_len_63` | 正 | TCP/IPv4 | ProfileToken 63 字符（maxLength 64 的 -1 邻位，D-11） | common.xsd tt:ReferenceToken maxLength=64+需求 v1.3 边界相邻值 | 9 |
| 51 | `onvif_token_len_64` | 正 | TCP/IPv4 | ProfileToken 64 字符满值（maxLength 64） | common.xsd tt:ReferenceToken maxLength=64 | 9 |
| 52 | `onvif_long_message_id` | 正 | TCP/IPv4 | 完整 urn:uuid: 36 字符 MessageID + RelatesTo 同值回带 | 设计§8 | 9 |
| 53 | `onvif_ipv6_transport` | 正 | TCP/IPv6 | IPv6 独立 fixture 基线（offset 74） | 设计§2/§8 | 9 |
| 54 | `onvif_ipv6_media_get_profiles` | 正 | TCP/IPv6 | IPv6 media 操作变体（v6 覆盖加强） | 设计§2/§8 | 9 |
| 55 | `onvif_multi_session` | 正 | TCP/IPv4 | 多会话展开：两会话各 1 事务、状态互不串用（C-11 钉死 18=9+9） | 设计§5/§8 | 18 |
| 56 | `onvif_concurrent_sessions` | 正 | TCP/IPv4 | 并发会话交错回放：双客户端四元组（C-4 翻案纳入） | 设计§6 v2.1（cwmp⑦/doh #27 同判例） | 18 |
| 57 | `onvif_mss_large_capabilities` | 正 | TCP/IPv4 | 大 GetCapabilities 响应跨 MSS 分段重组 | 设计§3.7/§8 | 11 |
| 58 | `onvif_neg_soap_envelope_ns` | 负 | — | envelope 命名空间写为 SOAP 1.1（schemas.xmlsoap.org/soap/envelope/） | SOAP 1.2 钉死（设计§1/§3.2） | — |
| 59 | `onvif_neg_soap_truncated` | 负 | — | XML 截断：envelope/操作元素未闭合 | 设计§3.2/§7 | — |
| 60 | `onvif_neg_soap_body_missing` | 负 | — | s:Body 缺失（仅 Header） | SOAP 1.2 Part 1 §5（Body 必需） | — |
| 61 | `onvif_neg_soap_header_order` | 负 | — | s:Header 位于 s:Body 之后 | SOAP 1.2 Part 1 §5（Header 先于 Body） | — |
| 62 | `onvif_neg_content_type` | 负 | — | Content-Type 为 text/xml（SOAP 1.1 形态） | 设计§3.1（钉死 soap+xml） | — |
| 63 | `onvif_neg_charset_missing` | 负 | — | Content-Type 缺 charset=utf-8 参数 | Core Spec §5.10.1 | — |
| 64 | `onvif_neg_charset_wrong` | 负 | — | charset=gbk（非 UTF-8） | Core Spec §5.10.1 | — |
| 65 | `onvif_neg_action_mismatch` | 负 | — | 事件声明 action 与 body 操作不一致（action=GetCapabilities 而 body=GetProfiles） | 设计§3.3 | — |
| 66 | `onvif_neg_action_suffix` | 负 | — | 事件声明请求 Action 尾缀已是 Response（违反去 Request 尾缀+Response 派生规则） | 设计§3.3 D-1 规则 | — |
| 67 | `onvif_neg_addressing_action` | 负 | — | 请求缺 wsa:Action | WS-Addressing+设计§3.3 | — |
| 68 | `onvif_neg_addressing_message_id` | 负 | — | 请求缺 wsa:MessageID | WS-Addressing 1.0 | — |
| 69 | `onvif_neg_addressing_relates` | 负 | — | 响应 RelatesTo ≠ 请求 MessageID | WS-Addressing 1.0 request-response | — |
| 70 | `onvif_neg_addressing_ns` | 负 | — | wsa 命名空间非 2005/08/addressing | Core Spec §5.3 Table 2 | — |
| 71 | `onvif_neg_operation_unknown` | 负 | — | 未知操作名（如 GetFooBar） | WSDL 实测（操作全集外） | — |
| 72 | `onvif_neg_operation_ns` | 负 | — | media 操作声明在 device 服务下（服务/命名空间不匹配） | WSDL 实测（tns 实测） | — |
| 73 | `onvif_neg_service_unknown` | 负 | — | service 声明不在四服务内（如 imaging） | 设计§1/§3.5（本版四服务） | — |
| 74 | `onvif_neg_parameter_stream_setup` | 负 | — | GetStreamUri 缺 StreamSetup 必选参数 | WSDL 实测 | — |
| 75 | `onvif_neg_parameter_profile_token` | 负 | — | GetStreamUri 缺 ProfileToken 必选参数 | WSDL 实测 | — |
| 76 | `onvif_neg_parameter_timeout` | 负 | — | PullMessages 缺 Timeout 必选参数 | WSDL 实测 | — |
| 77 | `onvif_neg_parameter_message_limit` | 负 | — | PullMessages 缺 MessageLimit 必选参数 | WSDL 实测 | — |
| 78 | `onvif_neg_parameter_duration` | 负 | — | Timeout 声明非 duration 文本（如 5s/now） | xs:duration | — |
| 79 | `onvif_neg_auth_missing` | 负 | — | READ_SYSTEM+ 事务无 auth 声明且无 401 往返声明 | Core Spec §5.9 | — |
| 80 | `onvif_neg_token_nonce` | 负 | — | UsernameToken 缺 Nonce | Core Spec §5.9.5（nonce+created 强制） | — |
| 81 | `onvif_neg_token_created` | 负 | — | UsernameToken 缺 Created | Core Spec §5.9.5 | — |
| 82 | `onvif_neg_carrier_layer` | 负 | — | 层链缺 http（tcp→onvif 直连） | 设计§2 | — |
| 83 | `onvif_neg_carrier_port` | 负 | — | 端口/载体矛盾（如 profile 声明明文 HTTP 配 443） | 设计§2 | — |
| 84 | `onvif_neg_carrier_wsdiscovery` | 负 | — | WS-Discovery UDP 载体误配为主链 | 设计§1 边界 | — |
| 85 | `onvif_neg_fault_code` | 负 | — | Fault 响应缺 s:Code | SOAP 1.2 §5.4 | — |
| 86 | `onvif_neg_fault_reason` | 负 | — | Fault 响应缺 s:Reason | SOAP 1.2 §5.4 | — |
| 87 | `onvif_neg_fault_value` | 负 | — | Code/Value 不在 SOAP 1.2 值域（如 env:Foo） | SOAP 1.2 Part 1 §7 | — |
| 88 | `onvif_neg_fault_subcode` | 负 | — | Subcode 值缺 ter: 前缀/命名空间（裸 NotAuthorized） | Core Spec Table 4 | — |
| 89 | `onvif_neg_length_truncation` | 负 | — | envelope 渲染截断（闭合缺失致字节数与声明不符） | 设计§3.7 | — |
| 90 | `onvif_neg_length_content_length` | 负 | — | Content-Length ≠ 渲染字节数 | HTTP/1.1 语义 | — |
| 91 | `onvif_neg_subscription_source` | 负 | — | PullMessages wsa:To 的 same_as_response 指向非 Create 事件或不存在事件 | 设计§3.5 | — |
| 92 | `onvif_neg_subscription_cross_session` | 负 | — | 订阅引用跨会话（引用他会话事件） | 设计§5 | — |
| 93 | `onvif_neg_token_range` | 负 | — | ProfileToken 声明 65 字符（maxLength 64 +1 越界） | common.xsd maxLength=64+需求 v1.3 边界相邻值 | — |
| 94 | `onvif_neg_message_limit_range` | 负 | — | MessageLimit 声明 2147483648（xs:int 满值 +1 越界） | xs:int+需求 v1.3 边界相邻值 | — |
| 95 | `onvif_neg_wsnt_ns` | 负 | — | 事件操作 wsnt 命名空间 URI 错（非 docs.oasis-open.org/wsn/b-2） | WS-BaseNotification b-2（D-2 实测） | — |

## 3. 线上编码和偏移断言

层链 `[tcp, http, onvif]`，无 VLAN/IP options/TCP options 时 HTTP 起行 IPv4 offset 54、IPv6 offset 74。**SOAP envelope 在 HTTP body 内，偏移不固定**：body 起点 = 54/74 + 该 fixture 固定 HTTP 头集合字节长 + 2（CRLF 空行；头集合由配置钉死，偏移可预算）。断言分层：

1. **HTTP 起行与头（fields 权威断言）**：请求帧 offset 54 起 ASCII `POST /onvif/device_service HTTP/1.1`（hex `50 4F 53 54 20 2F 6F 6E 76 69 66 2F 64 65 76 69 63 65 5F 73 65 72 76 69 63 65 20`）；字段断言 `http.request.method=POST`、`http.request.uri.path`、`http.content_type` 以 `application/soap+xml` 开头且含 `charset=utf-8`、`http.content_length`=`http.file_data` 字节长、`http.host`、`http.connection`（单事务/末事务 `close`、多事务逐请求 `keep-alive`）、`tcp.dstport`（非默认端口例）。**非 2xx 错误响应（fixture 决策形态）**：`http.response.code`=400/401/405/415 + `http.content_length=0` + 无 `http.file_data`；401 另有 `http.www_authenticate` 含 `Digest realm=`/`nonce=`/`qop=auth`/`algorithm=MD5`/`opaque=`；400 认证 Fault（#37）与 500 Fault（#38）**带 envelope**（§3.6 两形态）。
2. **SOAP envelope（frames hex + http.file_data 双通道）**：`http.file_data` nonzero 证明 body 存在；envelope 结构用 body 起点稳定 ASCII 前缀：`3C 3F 78 6D 6C`（`<?xml`）、`3C 73 3A 45 6E 76 65 6C 6F 70 65`（`<s:Envelope`，#9 前缀变体例除外）、`77 77 77 2E 77 33 2E 6F 72 67 2F 32 30 30 33 2F 30 35 2F 73 6F 61 70 2D 65 6E 76 65 6C 6F 70 65`（envelope URI）、`77 77 77 2E 6F 6E 76 69 66 2E 6F 72 67 2F 76 65 72 31 30 2F 64 65 76 69 63 65 2F 77 73 64 6C`（tds）、`76 65 72 31 30 2F 6D 65 64 69 61 2F 77 73 64 6C`（trt）、`76 65 72 32 30 2F 70 74 7A 2F 77 73 64 6C`（tptz ver20）、`64 6F 63 73 2E 6F 61 73 69 73 2D 6F 70 65 6E 2E 6F 72 67 2F 77 73 6E 2F 62 2D 32`（wsnt b-2，D-2）。**TCP 分段边界不是 HTTP/SOAP 边界**：跨段先按 `tcp.stream` 重组再断言。
3. **WS-Addressing/认证元素**：`<wsa:Action`（`3C 77 73 61 3A 41 63 74 69 6F 6E`）、`<wsa:MessageID`、`<wsa:RelatesTo`、`<wsa:To` 以 frames 字节断言；响应 Action 派生断言 = 请求 Action 文本去尾缀 `Request`（若有）+ `Response`（D-1，#28/#31/#32 落地）。401 挑战 `http.www_authenticate` 含 `Digest`；重发请求 `http.authorization` 含 `Digest`；UsernameToken 的 `<UsernameToken`/`<Username`/`<Password Type=…#PasswordDigest`/`<Nonce`/`<Created` 与 secext/utility 命名空间 URI hex。
4. **has_payload 语义**：权威断言 = `http.file_data` nonzero + body 起点 envelope hex 前缀，二者齐备才算有 SOAP 载荷；`frame.len>80` 只作宽松代理，不得以包数/PSH 替代。
5. **多会话/并发包号规则**：`sessions[]` 多会话展开整块回放（第二会话握手包号 = 前会话总包数 + 1）；`concurrent: true` 交错回放（#56）；跨会话关联断言用 `tcp.stream` 区分，不硬编码全局包号。

## 4. 正例逐项断言契约

约定 packet_count 见 §2 表；以下 fields/frames 为最低断言集，实现期可增不可减。默认 fixture 地址 `192.0.2.67 → 198.51.100.67`、`tcp.dstport=80`；服务路径 `/onvif/device_service`、`/onvif/media_service`、`/onvif/event_service`、`/onvif/ptz_service`；envelope 命名空间 `http://www.w3.org/2003/05/soap-envelope`、wsa `http://www.w3.org/2005/08/addressing`、wsnt `http://docs.oasis-open.org/wsn/b-2`（D-2）；前缀 fixture 钉死 `s:`/`wsa:`/`wsnt:`/`tds:`/`trt:`/`tev:`/`tptz:`/`tt:`（#9 前缀变体例除外）。`same_as_response` 指同 `tcp.stream` 内后序事务引用前序响应值。

1. **`onvif_ipv4_get_system_date_and_time`**（TCP/IPv4，packet_count=9）：握手；请求帧 `http.request.method=POST`、`http.request.uri.path=/onvif/device_service`、`http.content_type` 含 `application/soap+xml` 与 `charset=utf-8`、`http.file_data` nonzero + body 起点 `<?xml`/`<s:Envelope`/envelope 命名空间 URI hex、`<tds:GetSystemDateAndTime` hex、`<wsa:Action` 含 `GetSystemDateAndTime`、`<wsa:MessageID` 存在；响应 `http.response.code=200`、`<tds:GetSystemDateAndTimeResponse` hex、`<tt:UTCDateTime` 存在（§8.3.6 设备必须提供；包装元素 tds:、SystemDateTime 载荷元素 tt:——RN-2 混排规则）、`<wsa:RelatesTo` 文本=请求 MessageID；挥手。PRE_AUTH 无 `http.authorization`/无 `<Security`。
2. **`onvif_device_get_capabilities`**（TCP/IPv4，packet_count=9）：请求 `<tds:GetCapabilities` + `<tds:Category>All</tds:Category>`（参数带服务前缀，elementFormDefault=qualified）；响应 `<tds:GetCapabilitiesResponse` + `<tds:Capabilities` hex、Media/Events/PTZ 三服务 XAddr 存在（fixture 钉死 `http://198.51.100.67/onvif/{media,event,ptz}_service`）；RelatesTo 关联；PRE_AUTH 无凭据。
3. **`onvif_device_get_device_information`**（TCP/IPv4，packet_count=9）：请求带 UsernameToken（见 #6 结构）；响应 `<tds:GetDeviceInformationResponse` hex、`Manufacturer`/`Model`/`FirmwareVersion`/`SerialNumber`/`HardwareId` 五元素齐且有序（WSDL sequence 无 minOccurs=0），值 fixture 预配置 `Example`/`IPC-67`/`1.0.0`/`SN0000067`/`HW-67`（帧字节 ASCII）；RelatesTo 关联。
4. **`onvif_device_get_network_interfaces`**（TCP/IPv4，packet_count=9）：请求带 UsernameToken；响应 `<tds:GetNetworkInterfacesResponse` hex + `<tds:NetworkInterfaces token="nic_1">` hex（**tds: 本地元素**、token 为 tt:DeviceEntity 继承属性）+ `<tt:Enabled>true</tt:Enabled>` 子元素；**不出现** `<tt:InterfaceToken`（臆造元素，响应形状无此元素）；RelatesTo 关联。
5. **`onvif_network_interfaces_multi`**（TCP/IPv4，packet_count=9）：响应含 `<tds:NetworkInterfaces token="nic_1">` 与 `<tds:NetworkInterfaces token="nic_2">` 两实例（1..n 多实例合法），token 值 fixture 预配置且 distinct；其余同 #4。
6. **`onvif_ws_security_usernametoken`**（TCP/IPv4，packet_count=9）：单笔带认证事务（GetDeviceInformation）：`<UsernameToken`/`<Username>admin</Username>`/`<Password Type="…#PasswordDigest">`/`<Nonce EncodingType="…#Base64Binary">`/`<Created` 全存在；secext 命名空间 URI `docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd` hex；**nonce 与 created 并存**（缺一即负例）；Password/Nonce 为 base64 不透明（nonzero），不验证摘要正确性。
7. **`onvif_usernametoken_created_namespace`**（TCP/IPv4，packet_count=9）：同 #6 fixture；专项断言 `<Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">` 的 utility 命名空间 URI hex（`wssecurity-utility-1.0.xsd`）存在于请求帧。
8. **`onvif_soap12_envelope_structure`**（TCP/IPv4，packet_count=9）：单笔 PRE_AUTH 事务；`<?xml version="1.0" encoding="UTF-8"?>` 声明前缀、`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"` URI hex、Header 闭合先于 Body 开（字节序）、Body 内单操作元素、`http.content_type` 恰 `application/soap+xml; charset=utf-8`、无 `SOAPAction:` 头行、body 不含 `schemas.xmlsoap.org/soap/encoding/` 子串。
9. **`onvif_soap12_prefix_variant`**（TCP/IPv4，packet_count=9）：同 #8 fixture 但 envelope 前缀渲染为 `soapenv:`（`<soapenv:Envelope`）；断言命名空间 URI `www.w3.org/2003/05/soap-envelope` hex 仍存在、`<tds:` 服务前缀不受影响、`<s:Envelope` **不**出现——判别靠 URI 不靠前缀。
10. **`onvif_ws_addressing_correlation`**（TCP/IPv4，packet_count=9）：请求 `<wsa:Action>` 文本恰 `http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime`（frames 字节）、`<wsa:MessageID` 以 `urn:uuid:` 开头、wsa 命名空间 `www.w3.org/2005/08/addressing` hex；响应 `<wsa:Action>` = 请求 Action 去尾缀 Request（若有）+ `Response`、`<wsa:RelatesTo` 文本=请求 MessageID（same_as）。
11. **`onvif_http_401_digest_challenge`**（TCP/IPv4，packet_count=11）：事务 1 GetDeviceInformation 无凭据→响应 `http.response.code=401` + `http.www_authenticate` 含 `Digest`/`realm=`/`nonce=`/`qop=auth`/`algorithm=MD5`/`opaque=`（全参数 fixture 钉死）且无 envelope（`http.file_data` 零）；事务 2 同操作携带 `http.authorization` 含 `Digest`→响应 200 + GetDeviceInformationResponse；严格交替。
12. **`onvif_http_400_malformed_no_body`**（TCP/IPv4，packet_count=9）：本例为响应侧编排：请求为正常 POST，fixture 声明设备回 400 空（响应形态断言点在响应侧，Table 5 语义）；响应 `http.response.code=400`、`http.content_length=0`、无 `http.file_data`、无 `Content-Type` 头（fixture 决策：Table 5 仅钉状态码语义，响应形态本版钉死为空体）；与 400 认证 Fault（#37，带 envelope）不混用。
13. **`onvif_http_405_method_not_allowed`**（TCP/IPv4，packet_count=9）：响应 `http.response.code=405`、`http.content_length=0`、无 `http.file_data`、无 Content-Type（同 #12 fixture 决策）；请求帧 `http.request.method=PUT`（Table 5 语义：方法非 POST/GET；事件编排显式声明，引擎照剧本回放）。
14. **`onvif_http_415_unsupported_media`**（TCP/IPv4，packet_count=9）：响应 `http.response.code=415`、`http.content_length=0`、无 `http.file_data`（同 #12 fixture 决策）；请求 `http.content_type=text/xml`（Table 5 语义：不支持的封装；合法错误事件非 planner error）。
15. **`onvif_http_host_explicit`**（TCP/IPv4，packet_count=9）：请求 `http.host=onvif.example.com`（fixture 显式域名，非 dst_ip 缺省）；其余断言面同 #1。
16. **`onvif_single_transaction_connection_close`**（TCP/IPv4，packet_count=9）：单笔事务会话（GetSystemDateAndTime）；断言请求 `http.connection=close`（单事务即末事务，本版钉死）且响应后挥手 4 帧。
17. **`onvif_port_nondefault`**（TCP/IPv4，packet_count=9）：`tcp.dstport=8080`（端口由配置覆盖，planner 不得静默改写）；其余断言面同 #1。
18. **`onvif_http_keepalive_multi_transaction`**（TCP/IPv4，packet_count=13）：单 `tcp.stream` 承载 GetSystemDateAndTime→GetCapabilities→GetProfiles；请求/响应 1:1 交替无 pipelining、三事务 MessageID distinct、各响应 RelatesTo 配对本请求、各请求 `http.connection=keep-alive`、仅末事务 `close`；末响应后挥手。
19. **`onvif_media_get_profiles`**（TCP/IPv4，packet_count=9）：请求 `http.request.uri.path=/onvif/media_service`、`<trt:GetProfiles` hex、`<wsa:Action` 含 `ver10/media/wsdl/GetProfiles`；响应 `<trt:GetProfilesResponse` hex + `<trt:Profiles token="profile_1">` hex（**响应元素名为复数 Profiles、tt:Profile 实例带 token 属性**——C-1 修正，`<trt:Profile ` 单数形态不出现）+ `<tt:Name>mainStream</tt:Name>` + `<tt:VideoEncoderConfiguration` 子结构（fixture H264/1920/1080/25）；RelatesTo 关联。
20. **`onvif_media_get_profiles_multi`**（TCP/IPv4，packet_count=9）：响应含 `<trt:Profiles token="profile_1">` 与 `<trt:Profiles token="profile_2">` 两实例（0..n 多实例合法），token fixture 预配置且 distinct；其余同 #19。
21. **`onvif_media_get_stream_uri`**（TCP/IPv4，packet_count=11）：两事务：事务 1 同 #19（返回 profile_1）；事务 2 请求 `<trt:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream><tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup>` + `<trt:ProfileToken>profile_1</trt:ProfileToken>`（值=事务 1 响应 token，same_as_response 关联断言）；响应 `<trt:GetStreamUriResponse` + `<trt:MediaUri><tt:Uri>rtsp://198.51.100.67:554/profile_1/stream1</tt:Uri>`——**仅返回字段断言，不派生 RTSP 数据面**（包尾即挥手，无后续媒体帧）。
22. **`onvif_media_get_snapshot_uri`**（TCP/IPv4，packet_count=9）：单事务；请求 `<trt:GetSnapshotUri` + `<trt:ProfileToken>profile_1</trt:ProfileToken>`（fixture 直给）；响应 `<trt:MediaUri><tt:Uri>http://198.51.100.67/onvif/snapshot/profile_1</tt:Uri>`（http 形态，仅返回字段断言）。
23. **`onvif_ptz_continuous_move`**（TCP/IPv4，packet_count=9）：请求 `http.request.uri.path=/onvif/ptz_service`、`<tptz:ContinuousMove` + `<tptz:ProfileToken` + `<tptz:Velocity><tt:PanTilt x= y=/>`（**Velocity 类型 tt:PTZSpeed**，C-1 同批 WSDL 实测修正——`tt:PTZVector` 不出现）；命名空间 URI `www.onvif.org/ver20/ptz/wsdl` hex；响应 `<tptz:ContinuousMoveResponse`（空 body 元素合法）；RelatesTo 关联。
24. **`onvif_ptz_continuous_move_timeout`**（TCP/IPv4，packet_count=9）：同 #23 fixture 另加 `<tptz:Timeout>PT10S</tptz:Timeout>` 可选参数（WSDL xs:duration）；断言其存在与 duration 文本；其余同 #23。
25. **`onvif_ptz_move_stop_sequence`**（TCP/IPv4，packet_count=11）：两事务（Move 先于 Stop，事件编排顺序）：事务 1 同 #23、事务 2 `<tptz:Stop` + ProfileToken→`<tptz:StopResponse`；两事务 MessageID distinct、RelatesTo 各自配对；Move 帧包序先于 Stop 帧。
26. **`onvif_ptz_stop_no_flags`**（TCP/IPv4，packet_count=9）：请求仅 `<tptz:Stop` + `<tptz:ProfileToken>`（PanTilt/Zoom 双省略——合法可选）；响应 `<tptz:StopResponse`；RelatesTo 关联。
27. **`onvif_ptz_stop_flags`**（TCP/IPv4，packet_count=9）：请求 `<tptz:Stop` + ProfileToken + `<tptz:PanTilt>true</tptz:PanTilt>` + `<tptz:Zoom>true</tptz:Zoom>`；响应 `<tptz:StopResponse`；RelatesTo 关联。
28. **`onvif_events_create_pullpoint_subscription`**（TCP/IPv4，packet_count=9）：请求 `http.request.uri.path=/onvif/event_service`、`<tev:CreatePullPointSubscription` + `<tev:InitialTerminationTime>PT1M</tev:InitialTerminationTime>`、`<wsa:Action` 含 `EventPortType/CreatePullPointSubscriptionRequest`（§9.10.3 形态）；响应 `<tev:CreatePullPointSubscriptionResponse` hex + **响应 `<wsa:Action` 含 `CreatePullPointSubscriptionResponse`（去 Request 尾缀+Response，D-1）** + `<tev:SubscriptionReference><wsa:Address>` 存在（fixture `http://198.51.100.67/onvif/subscription?Idx=0`）+ `<wsnt:CurrentTime`/`<wsnt:TerminationTime` 存在且 `Z` 结尾（UTC）。
29. **`onvif_events_create_with_filter`**（TCP/IPv4，packet_count=9）：同 #28 fixture 另加 `<tev:Filter><wsnt:TopicExpression Dialect="http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet">tns1:Device/Trigger/DigitalInput</wsnt:TopicExpression></tev:Filter>`；断言 Filter/TopicExpression/Dialect 属性存在；其余同 #28。
30. **`onvif_events_create_absolute_termination`**（TCP/IPv4，packet_count=9）：同 #28 fixture 但 `<tev:InitialTerminationTime>2026-09-02T00:00:00Z</tev:InitialTerminationTime>`（绝对 dateTime 形态）；断言其文本与 UTC `Z`；其余同 #28。
31. **`onvif_events_create_to_pull_correlation`**（TCP/IPv4，packet_count=11）：同会话两事务：事务 1 同 #28（SubscriptionReference=`http://198.51.100.67/onvif/subscription?Idx=0`）；事务 2 PullMessages 请求 `<wsa:To>` 文本 = 事务 1 响应 SubscriptionReference 地址（**same_as_response 端到端关联断言**，非 fixture 直给）；响应 RelatesTo 配对。
32. **`onvif_events_pull_messages`**（TCP/IPv4，packet_count=9）：请求 `<tev:PullMessages` + `<tev:Timeout>PT5S</tev:Timeout>` + `<tev:MessageLimit>2</tev:MessageLimit>`、`<wsa:To>` = 订阅端点 fixture 值、`<wsa:Action` 含 `PullPointSubscription/PullMessagesRequest`（§9.10.5 形态）；响应 `<tev:PullMessagesResponse` + **响应 Action 含 `PullMessagesResponse`（D-1）** + `<tev:CurrentTime`/`<tev:TerminationTime` + `<wsnt:NotificationMessage` 一条（`<wsnt:Topic Dialect=` + `<tt:SimpleItem Name= Value=`，fixture 预配置）；wsnt 命名空间 `docs.oasis-open.org/wsn/b-2` hex（D-2）。
33. **`onvif_events_pull_messages_timeout_zero`**（TCP/IPv4，packet_count=9）：同 #32 fixture 但响应无 `<wsnt:NotificationMessage`（空列表合法）；`<tev:CurrentTime`/`<tev:TerminationTime` 仍存在；`http.response.code=200`（HTTP 成功≠有消息）；RelatesTo 关联。
34. **`onvif_events_pull_messages_limit_1`**（TCP/IPv4，packet_count=9）：同 #32 fixture 但 `<tev:MessageLimit>1</tev:MessageLimit>`（下界）；其余同 #32。
35. **`onvif_events_pull_messages_limit_int_max`**（TCP/IPv4，packet_count=9）：同 #32 fixture 但 `<tev:MessageLimit>2147483647</tev:MessageLimit>`（32-bit 有符号满值，帧字节 ASCII 精确）；其余同 #32。
36. **`onvif_events_pull_timeout_pt0s`**（TCP/IPv4，packet_count=9）：同 #32 fixture 但 `<tev:Timeout>PT0S</tev:Timeout>`（duration 零值合法边界）；响应零消息形态；其余同 #32。
37. **`onvif_fault_400_auth`**（TCP/IPv4，packet_count=9）：GetDeviceInformation 无凭据、fixture 声明设备仅支持 UsernameToken 模式；响应 `http.response.code=400`（非 500）、`<s:Fault`/`<s:Code><s:Value>env:Sender</s:Value>`/`<s:Subcode><s:Value>ter:NotAuthorized</s:Value>`（ter URI `www.onvif.org/ver10/error` hex）/`<s:Reason><s:Text xml:lang="en">Sender not Authorized`；Fault `<wsa:Action` 恰 `http://www.w3.org/2005/08/addressing/soap/fault`（§9.9）；RelatesTo 关联。
38. **`onvif_fault_500_no_such_service`**（TCP/IPv4，packet_count=9）：GetCapabilities 携带设备不支持类别（fixture 未实现 Analytics，请求 `<tds:Category>Analytics`）；响应 `http.response.code=500`、`<s:Code><s:Value>env:Receiver</s:Value>`、`<s:Subcode><s:Value>ter:ActionNotSupported</s:Value>` 及嵌套 `ter:NoSuchService`（子码组合与 Reason 文本实现期对 §8.1.2.4 核实）；Fault action URI 同 #37；RelatesTo 关联。
39. **`onvif_fault_full_form`**（TCP/IPv4，packet_count=9）：同 #37 fixture 另加 `<s:Node>…</s:Node><s:Role>…</s:Role><s:Detail>…</s:Detail>`（可选元素全形合法）；断言三元素存在且 Reason 仍在 Detail 之外（SOAP 1.2 结构顺序 Code→Reason→Node→Role→Detail）。
40. **`onvif_capabilities_category_device`**（TCP/IPv4，packet_count=9）：同 #2 fixture 但 `<tds:Category>Device</tds:Category>`；响应 200 + Capabilities 结构；RelatesTo 关联。
41. **`onvif_capabilities_category_events`**（TCP/IPv4，packet_count=9）：同 #40，Category=Events。
42. **`onvif_capabilities_category_imaging`**（TCP/IPv4，packet_count=9）：同 #40，Category=Imaging。
43. **`onvif_capabilities_category_media`**（TCP/IPv4，packet_count=9）：同 #40，Category=Media。
44. **`onvif_capabilities_category_ptz`**（TCP/IPv4，packet_count=9）：同 #40，Category=PTZ。
45. **`onvif_capabilities_category_analytics`**（TCP/IPv4，packet_count=9）：同 #40，Category=Analytics（fixture 此例设备支持 Analytics→200；与 #38 不支持→500 构成同参数双形态）。
46. **`onvif_capabilities_multi_category`**（TCP/IPv4，packet_count=9）：同 #2 fixture 但请求含 `<tds:Category>Device</tds:Category>` 与 `<tds:Category>Events</tds:Category>` 两参数元素（0..n 多值合法）；响应 200。
47. **`onvif_date_time_daylight_timezone`**（TCP/IPv4，packet_count=9）：同 #1 fixture 但响应 `<tt:DaylightSavings>true</tt:DaylightSavings>`（**拼写 DaylightSavings**，schema 实测；tt: 前缀——RN-2）+ `<tt:TimeZone><tt:TZ>CST-8</tt:TZ></tt:TimeZone>`；断言两元素与 TZ 文本。
48. **`onvif_date_time_localtime`**（TCP/IPv4，packet_count=9）：同 #1 fixture 但响应另含 `<tt:LocalDateTime>`（可选元素携带形态，tt: 前缀——RN-2；子结构 `<tt:Time>`/`<tt:Date>` 存在）。
49. **`onvif_date_time_manual`**（TCP/IPv4，packet_count=9）：同 #1 fixture 但响应 `<tt:DateTimeType>Manual</tt:DateTimeType>`（tt: 前缀——RN-2；值域 NTP/Manual 双值覆盖的第二值）；其余同 #1。
50. **`onvif_token_len_63`**（TCP/IPv4，packet_count=9）：GetSnapshotUri 使用 63 字符 token（fixture `tok_`+59 hex）；请求 `<trt:ProfileToken>` 文本完整 63 字符（帧字节 ASCII）；响应 MediaUri 含该 token 子串。
51. **`onvif_token_len_64`**（TCP/IPv4，packet_count=9）：同 #50 fixture 但 64 字符（`tok_`+60 hex）满值；断言完整值与 MediaUri 子串。
52. **`onvif_long_message_id`**（TCP/IPv4，packet_count=9）：fixture 固定完整 `urn:uuid:6fa459ea-ee8a-3ca4-894e-db77e160355e` 形态 MessageID；请求/响应断言该完整值出现且响应 `<wsa:RelatesTo` 同值回带（帧字节 ASCII 精确）。
53. **`onvif_ipv6_transport`**（TCP/IPv6，packet_count=9）：fixture `2001:db8::67 → 2001:db8::100:67`（显式给出，不从 IPv4 推导）；`ipv6.nxt=6`、HTTP 起行 offset 74、POST/GetSystemDateAndTime 形状同 #1、envelope 骨架字节与 #1 一致；不出现 `ip.version=4`。
54. **`onvif_ipv6_media_get_profiles`**（TCP/IPv6，packet_count=9）：IPv6 fixture 上 GetProfiles 全流程；URI 路径 `/onvif/media_service`、XAddr/响应结构同 #19、`ipv6.nxt=6`；RelatesTo 关联。
55. **`onvif_multi_session`**（TCP/IPv4，packet_count=18）：会话 1（src_port=4067，GetSystemDateAndTime 单事务=9 包）、会话 2（src_port=4068，GetProfiles 单事务=9 包）；两 `tcp.stream` distinct、第二会话握手包号=10（前会话总包数+1）、两会话 MessageID 空间独立（distinct_values）、各响应 RelatesTo 匹配本会话请求（无串用）。
56. **`onvif_concurrent_sessions`**（TCP/IPv4，packet_count=18）：`concurrent: true` 双会话交错回放（src_port 4067/4068）；断言两 `tcp.stream` 交错但各会话事务配对完整、MessageID/订阅上下文互不串用、各响应 RelatesTo 匹配本会话请求——生成器级多设备并发不违反单会话串行。
57. **`onvif_mss_large_capabilities`**（TCP/IPv4，packet_count=11）：响应 envelope ≥1500 字节（多服务 XAddr+能力条目）、MSS 压小跨 ≥2 段；`tcp.len` 分布、按 `tcp.stream` 重组后末帧 `http.file_data` 完整、`http.content_length`=重组 body 字节数、Capabilities 闭合标签存在、分段边界不切 SOAP 元素（重组前单段不含完整 `</s:Envelope>`——以 fixture MSS 校准，不满足则降级单断言）。

**正例总则**：每条实现后至少含 `packet_count`/`min_packets`、载体与方向断言、`has_payload`（`http.file_data` nonzero + envelope hex 前缀）、可观察 fields（`http.*` 实测字段）、稳定 frames（body 前缀与关键 token 字节）；动态值只用存在与关联断言。合法协议事件（HTTP 400/401/405/415、SOAP Fault、PullMessages 超时零消息、PRE_AUTH 免认证）均为正例形态；只有配置、线格式、状态、关联、长度错误进入负例（§5）。

## 5. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP/HTTP 外壳的假成功；执行期 `expect` 严格只有 `expect_error`、`error_contains`。锚词与设计 §7 表一一对应（主锚词钉死，备选供实现期校准）：

| # | ID | `wire_fault` 注入口 | 故障输入 | 主锚词（备选） |
|---:|---|---|---|---|
| 58 | `onvif_neg_soap_envelope_ns` | `soap_envelope_ns` | envelope 命名空间写为 SOAP 1.1（schemas.xmlsoap.org/soap/envelope/） | `envelope`（namespace/soap） |
| 59 | `onvif_neg_soap_truncated` | `soap_truncated` | XML 截断：envelope/操作元素未闭合 | `xml`（truncate/envelope） |
| 60 | `onvif_neg_soap_body_missing` | `soap_body_missing` | s:Body 缺失（仅 Header） | `body`（envelope/soap） |
| 61 | `onvif_neg_soap_header_order` | `soap_header_order` | s:Header 位于 s:Body 之后 | `header`（order/envelope） |
| 62 | `onvif_neg_content_type` | `content_type` | Content-Type 为 text/xml（SOAP 1.1 形态） | `content-type`（media） |
| 63 | `onvif_neg_charset_missing` | `charset_missing` | Content-Type 缺 charset=utf-8 参数 | `charset`（content-type） |
| 64 | `onvif_neg_charset_wrong` | `charset_wrong` | charset=gbk（非 UTF-8） | `charset`（encoding） |
| 65 | `onvif_neg_action_mismatch` | `action_mismatch` | 事件声明 action 与 body 操作不一致（action=GetCapabilities 而 body=GetProfiles） | `action`（operation） |
| 66 | `onvif_neg_action_suffix` | `action_suffix` | 事件声明请求 Action 尾缀已是 Response（违反去 Request 尾缀+Response 派生规则） | `action`（response） |
| 67 | `onvif_neg_addressing_action` | `addressing_action` | 请求缺 wsa:Action | `addressing`（action） |
| 68 | `onvif_neg_addressing_message_id` | `addressing_message_id` | 请求缺 wsa:MessageID | `message`（addressing） |
| 69 | `onvif_neg_addressing_relates` | `addressing_relates` | 响应 RelatesTo ≠ 请求 MessageID | `relates`（correlation） |
| 70 | `onvif_neg_addressing_ns` | `addressing_ns` | wsa 命名空间非 2005/08/addressing | `addressing`（namespace） |
| 71 | `onvif_neg_operation_unknown` | `operation_unknown` | 未知操作名（如 GetFooBar） | `operation`（unknown） |
| 72 | `onvif_neg_operation_ns` | `operation_ns` | media 操作声明在 device 服务下（服务/命名空间不匹配） | `namespace`（operation） |
| 73 | `onvif_neg_service_unknown` | `service_unknown` | service 声明不在四服务内（如 imaging） | `service`（unknown） |
| 74 | `onvif_neg_parameter_stream_setup` | `parameter_stream_setup` | GetStreamUri 缺 StreamSetup 必选参数 | `parameter`（missing） |
| 75 | `onvif_neg_parameter_profile_token` | `parameter_profile_token` | GetStreamUri 缺 ProfileToken 必选参数 | `parameter`（missing） |
| 76 | `onvif_neg_parameter_timeout` | `parameter_timeout` | PullMessages 缺 Timeout 必选参数 | `parameter`（missing） |
| 77 | `onvif_neg_parameter_message_limit` | `parameter_message_limit` | PullMessages 缺 MessageLimit 必选参数 | `parameter`（missing） |
| 78 | `onvif_neg_parameter_duration` | `parameter_duration` | Timeout 声明非 duration 文本（如 5s/now） | `parameter`（duration） |
| 79 | `onvif_neg_auth_missing` | `auth_missing` | READ_SYSTEM+ 事务无 auth 声明且无 401 往返声明 | `auth`（credential） |
| 80 | `onvif_neg_token_nonce` | `token_nonce` | UsernameToken 缺 Nonce | `nonce`（token） |
| 81 | `onvif_neg_token_created` | `token_created` | UsernameToken 缺 Created | `created`（token） |
| 82 | `onvif_neg_carrier_layer` | `carrier_layer` | 层链缺 http（tcp→onvif 直连） | `layer`（carrier） |
| 83 | `onvif_neg_carrier_port` | `carrier_port` | 端口/载体矛盾（如 profile 声明明文 HTTP 配 443） | `profile`（carrier） |
| 84 | `onvif_neg_carrier_wsdiscovery` | `carrier_wsdiscovery` | WS-Discovery UDP 载体误配为主链 | `carrier`（discovery） |
| 85 | `onvif_neg_fault_code` | `fault_code` | Fault 响应缺 s:Code | `fault`（code） |
| 86 | `onvif_neg_fault_reason` | `fault_reason` | Fault 响应缺 s:Reason | `reason`（fault） |
| 87 | `onvif_neg_fault_value` | `fault_value` | Code/Value 不在 SOAP 1.2 值域（如 env:Foo） | `code`（value） |
| 88 | `onvif_neg_fault_subcode` | `fault_subcode` | Subcode 值缺 ter: 前缀/命名空间（裸 NotAuthorized） | `subcode`（namespace） |
| 89 | `onvif_neg_length_truncation` | `length_truncation` | envelope 渲染截断（闭合缺失致字节数与声明不符） | `length`（truncate） |
| 90 | `onvif_neg_length_content_length` | `length_content_length` | Content-Length ≠ 渲染字节数 | `content-length`（length） |
| 91 | `onvif_neg_subscription_source` | `subscription_source` | PullMessages wsa:To 的 same_as_response 指向非 Create 事件或不存在事件 | `subscription`（reference） |
| 92 | `onvif_neg_subscription_cross_session` | `subscription_cross_session` | 订阅引用跨会话（引用他会话事件） | `correlation`（session） |
| 93 | `onvif_neg_token_range` | `token_range` | ProfileToken 声明 65 字符（maxLength 64 +1 越界） | `token`（length） |
| 94 | `onvif_neg_message_limit_range` | `message_limit_range` | MessageLimit 声明 2147483648（xs:int 满值 +1 越界） | `limit`（range） |
| 95 | `onvif_neg_wsnt_ns` | `wsnt_ns` | 事件操作 wsnt 命名空间 URI 错（非 docs.oasis-open.org/wsn/b-2） | `wsnt`（namespace） |

合法协议事件不进负例（防误报）：HTTP 401 挑战本身、400-Malformed/405/415 响应本身（Table 5，#12-14 正例化）、SOAP Fault 响应本身（Table 4 全子码）、PullMessages 超时零消息、GetCapabilities `ter:NoSuchService`、PRE_AUTH 免认证、MessageID 跨会话独立重复。

## 6. 五层覆盖映射（v1.3 行为面对照，按 ID 引用防错位）

| 层面 | 用例 ID | 说明 |
|---|---|---|
| 功能 | 基线/编码族（1-10）、HTTP 状态族（11-18）、操作族（19-39：device 3-5、auth 6-7、media 19-22、ptz 23-27、events 28-36、Fault 37-39） | 四服务 11 操作逐操作正例 + envelope/wsa/WSS 编码规则逐条 + Table 4/5 合法错误事件正例化；负例 §5 38 行逐错误分支（envelope×4、头×3、action×2、addressing×4、操作×3、参数×5、认证×3、载体×3、Fault×4、长度×2、订阅×2、值域×3） |
| 性能 | 57（MSS 大响应）、50-52（长 token/MessageID 上界） | 大报文跨分段重组；字段长度上界（ReferenceToken maxLength=64）；速率由框架既有配置承载 |
| 数据场景 | 值域族（34-36、40-46、47-49）、边界族（50-51） | CapabilityCategory 7 值全枚举、duration/int 边界（PT0S、1、2147483647）、DateTimeType 双值、ReferenceToken 63/64 邻位与满值、Fault 可选元素全形、前缀变体 |
| 地址与流 | 1（v4 单流基线）、53-54（v6）、55（多会话）、56（并发会话） | v4+v6 必覆盖；流关联显式不适用（媒体 URI 仅返回字段，设计 §3.5 声明）；多流不适用（HTTP/1.1 无 pipelining）；RST 不产生（设计 §5 声明，FIN 统一挥手） |
| 业务 | 接入首链（1/2）、认证读信息（3/4/11）、取流准备（19-22）、PTZ（23-27）、事件轮询（28-36）、错误路径（37-39） | 现网 NVR/客户端日常场景优先 |

## 7. 机器契约与静态检查

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/onvif.json` 通过；数组共 96 条：95 条语义用例（57 正 + 38 负）及 1 条 `onvif_neg_presence_top_level_onvif` presence 负例。机读审计确认 95 条语义用例的顶层仅有 `layers`，且层序为 `[ip,tcp,http,onvif]`；presence 负例故意保留顶层 `onvif` 与层内配置。
2. 95 条语义用例的业务配置均在 `layers[].onvif`，地址在 `layers.ip`、端口在 `layers.tcp`；presence 负例专门验证顶层旧键拒绝，不计入语义正负计数。ID、顺序与设计 §9 的 95 条语义清单一致。
3. 正例每条含 `packet_count`（或 `min_packets`）+ `fields` + `frames`；`fields` 只用 §1 实测存在的 tshark 字段，**不伪造 `onvif.*`/`soap.*`/`wsa.*`**；SOAP 断言用 §3 body 起点 hex 前缀约定（`http.file_data` + frames 双通道）。
4. 负例 `expect` 键集合恰为 `{expect_error, error_contains}`，不加 packet_count/fields；`error_contains` 用 §5 主锚词。
5. 断言包号引用跨会话/跨连接时用 `tcp.stream`+会话起点规则；动态值用 `same_as_packet`/`same_as_response`/`distinct_values`/`nonzero`。
6. 若实现期实证 tshark 对 `application/soap+xml` 自动内层 XML 解码（`xml.tag` 可用），四件套同步更新；未实证前不得把 `xml.*` 写进最低断言集。

## T1–T6 / C1–C6 静态闭环审计（2026-10-01）

本轮只完成设计、测试契约与 `cases/onvif.json` 的静态闭环；禁止修改 Go/schema/其他文档，未运行 suite、服务、MCP 或 NIC。D1–D8 设计项在上文既有规范、层链、事务、错误、性能和动态字段章节中已有依据；以下按机器 JSON 实测记录结果。

### T1–T6

| 项 | 静态核对 | 结论 |
|---|---|---|
| T1 规范/设计/JSON 回指 | 95 个语义 ID 与 §2/§9 顺序一致；D1–D8 依据保留 | 绿 |
| T2 存量去向 | 95 条语义用例保留；旧顶层业务映射迁入 `layers[].onvif`；presence 旧键保留为专门负例 | 绿 |
| T3 严格层链 | 94 条语义用例为 `[ip,tcp,http,onvif]`；`onvif_neg_carrier_layer` 故意为 `[ip,tcp,onvif]` 以验证缺失 HTTP 载体拒绝；地址仅在 ip、端口仅在 tcp、业务仅在 onvif 层 | 绿（含判死负例） |
| T4 正例契约 | 57 条均有 `packet_count`、`fields`、`frames`，断言使用实测 `http.*`/TCP/IP 字段与真实锚词 | 绿（静态） |
| T5 负例契约 | 38 条协议负例 `expect` 恰为 `expect_error` + `error_contains`；另 1 条 presence 负例同样为双键 | 绿（静态） |
| T6 运行期边界 | JSON 可解析；本轮未跑 suite/服务/MCP/NIC，不宣称 PCAP 或线口通过 | 待运行 |

### C1–C6

| 项 | 检查 | 结论 |
|---|---|---|
| C1 JSON/ID | 96 条唯一 ID；语义 95 = 57 正 + 38 负；presence 单独登记 | 绿 |
| C2 层链/顶层键 | 94 条语义用例为 `[ip,tcp,http,onvif]`；`onvif_neg_carrier_layer` 是故意缺 HTTP 的判死负例；95 条语义用例顶层仅 `layers`，唯一顶层 `onvif` 仅 presence 负例 | 绿（含判死负例） |
| C3 字段归属 | IP 地址在 `layers.ip`，TCP 端口在 `layers.tcp`，ONVIF 业务配置在 `layers.onvif` | 绿 |
| C4 失败路径 | 38 个 `wire_fault` 与 38 个错误锚词逐条对应；presence 负例保留并点名形状 | 绿（静态） |
| C5 动态/真实锚词 | MessageID、Nonce、时间和订阅引用按 nonzero/distinct/关联约定；frames 锚词来自 §3/§4 | 绿（静态） |
| C6 双输出/实测 | pcap 与 port_group/NIC 共用同一契约已写入设计和测试文档；本轮未执行真实输出 | 待运行 |

缺口迁入计划：G-ONVIF-1（层配置消费路径仍需 C1 代码接线确认）、G-ONVIF-2（95 条语义用例全量 suite + tshark 校准）、G-ONVIF-3（授权 NIC/port_group 同断言复验）、G-ONVIF-4（动态字段/多会话/MSS 实测校准）、G-ONVIF-5（性能六类场景：基线、目标规模、压力上限、长跑、并发交错、背压）。presence 负例不是缺口，必须保留。

本轮自审两轮：第一轮逐条核对 D1–D8、T1–T6、C1–C6、JSON 数量/ID/层链/顶层键/负例双键；第二轮复核动态字段、真实锚词、presence 负例形状、未运行边界与缺口迁入计划，末轮干净。

设计 §9、本文 §2 与 `onvif.json` 的 95 个语义 ID 保持同一顺序；JSON 另有 1 条独立 presence 负例，合计 96 条机器用例。95 条语义用例已完成层链迁移，presence 负例仅验证旧键拒绝，不改变语义清单：

```text
onvif_ipv4_get_system_date_and_time
onvif_device_get_capabilities
onvif_device_get_device_information
onvif_device_get_network_interfaces
onvif_network_interfaces_multi
onvif_ws_security_usernametoken
onvif_usernametoken_created_namespace
onvif_soap12_envelope_structure
onvif_soap12_prefix_variant
onvif_ws_addressing_correlation
onvif_http_401_digest_challenge
onvif_http_400_malformed_no_body
onvif_http_405_method_not_allowed
onvif_http_415_unsupported_media
onvif_http_host_explicit
onvif_single_transaction_connection_close
onvif_port_nondefault
onvif_http_keepalive_multi_transaction
onvif_media_get_profiles
onvif_media_get_profiles_multi
onvif_media_get_stream_uri
onvif_media_get_snapshot_uri
onvif_ptz_continuous_move
onvif_ptz_continuous_move_timeout
onvif_ptz_move_stop_sequence
onvif_ptz_stop_no_flags
onvif_ptz_stop_flags
onvif_events_create_pullpoint_subscription
onvif_events_create_with_filter
onvif_events_create_absolute_termination
onvif_events_create_to_pull_correlation
onvif_events_pull_messages
onvif_events_pull_messages_timeout_zero
onvif_events_pull_messages_limit_1
onvif_events_pull_messages_limit_int_max
onvif_events_pull_timeout_pt0s
onvif_fault_400_auth
onvif_fault_500_no_such_service
onvif_fault_full_form
onvif_capabilities_category_device
onvif_capabilities_category_events
onvif_capabilities_category_imaging
onvif_capabilities_category_media
onvif_capabilities_category_ptz
onvif_capabilities_category_analytics
onvif_capabilities_multi_category
onvif_date_time_daylight_timezone
onvif_date_time_localtime
onvif_date_time_manual
onvif_token_len_63
onvif_token_len_64
onvif_long_message_id
onvif_ipv6_transport
onvif_ipv6_media_get_profiles
onvif_multi_session
onvif_concurrent_sessions
onvif_mss_large_capabilities
onvif_neg_soap_envelope_ns
onvif_neg_soap_truncated
onvif_neg_soap_body_missing
onvif_neg_soap_header_order
onvif_neg_content_type
onvif_neg_charset_missing
onvif_neg_charset_wrong
onvif_neg_action_mismatch
onvif_neg_action_suffix
onvif_neg_addressing_action
onvif_neg_addressing_message_id
onvif_neg_addressing_relates
onvif_neg_addressing_ns
onvif_neg_operation_unknown
onvif_neg_operation_ns
onvif_neg_service_unknown
onvif_neg_parameter_stream_setup
onvif_neg_parameter_profile_token
onvif_neg_parameter_timeout
onvif_neg_parameter_message_limit
onvif_neg_parameter_duration
onvif_neg_auth_missing
onvif_neg_token_nonce
onvif_neg_token_created
onvif_neg_carrier_layer
onvif_neg_carrier_port
onvif_neg_carrier_wsdiscovery
onvif_neg_fault_code
onvif_neg_fault_reason
onvif_neg_fault_value
onvif_neg_fault_subcode
onvif_neg_length_truncation
onvif_neg_length_content_length
onvif_neg_subscription_source
onvif_neg_subscription_cross_session
onvif_neg_token_range
onvif_neg_message_limit_range
onvif_neg_wsnt_ns
```

## 9. 修订记录

- v1.0.0（2026-08-20）：旧稿首版（14 正 + 6 负）。
- v2.1.1（2026-09-01，RN 复验轮收尾）：rr-onvif 复验 22/24 CLOSED + 新发现四处修复——**RN-1**（CRITICAL）#21 GetStreamUri 请求断言改混合前缀精确形态 `<trt:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream><tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup>`（子元素为 onvif.xsd 类型元素 tt:、StreamType 枚举连字符；trt: 仅 media.wsdl 本地元素），§6 typedef 同步 `"stream": "RTP-Unicast"`；**RN-2**（CRITICAL）GetSystemDateAndTime 载荷元素五处 tds:→tt:（#1 `<tt:UTCDateTime`、#47 `<tt:DaylightSavings>`/`<tt:TimeZone>`、#48 `<tt:LocalDateTime>`、#49 `<tt:DateTimeType>`），设计 §3.5 混排规则入文；**RN-3**（MINOR）#12 措辞改纯响应侧编排表述；**D-3 残留**设计 §6 digest 引证 WSS §4.2。rr-onvif 关单复验判定 **clean**（confirmed findings = 0），结构回归 95 = 57 正 + 38 负不变。
- v2.0.0（2026-09-01）：v1.1 隔离审查轮重写（31 条 = 20 正 + 11 负），断言基线定为 `http.*` 实测字段 + frames hex 前缀双通道（无 `onvif.*`/`soap.*`/`wsa.*` 臆造字段）。
- v2.0.1（2026-09-01）：9 项审查修复（用例 15 改 400 认证 Fault、新增 21 号 500 Fault，32 条 = 21 正 + 11 负）。
- v2.1.0（2026-09-01，v1.3 重审修复轮）：rr-onvif 行为面 138 点全枚举重审（24 confirmed findings）后重出：32 条 → **95 条（57 正 + 38 负）**。关键修复：**C-1**（CRITICAL）用例 9 断言形状按 WSDL 实测修正——GetProfilesResponse 子元素为复数 `Profiles`（tt:Profile 实例、token 属性），删除互斥的单数 `<trt:Profile` 断言；**C-2**（CRITICAL）用例 4 修正为 `<tds:NetworkInterfaces token=…>`（devicemgmt.wsdl 本地元素）+ `<tt:Enabled>`，删除臆造元素 `<tt:InterfaceToken`；**C-3** pcap/NIC 双输出契约声明入 §1；**C-4** 并发会话翻案纳入（#56，cwmp⑦/doh #27 同判例）；**C-5** wsa:To ← Create 响应 same_as_response 端到端用例（#31）；**C-6** 边界相邻值整组补齐（token 63/64 正例 + 65 负例、MessageLimit 满值正例 + 越界负例、PT0S duration 边界）；**C-7** 非默认端口正例（#17，`tcp.dstport`）；**C-8** RST 不产生声明（设计 §5，FIN 统一挥手）；**C-9** 405/415/400-Malformed 合法错误响应正例化（#12-14，响应形态钉死为 fixture 决策）；**C-10** PullMessages 超时零消息正例（#33）；**C-11** 多会话用例文本与包数矛盾钉死（#55 = 9+9 各单事务）；**C-12** 行为面全枚举扩量 32→95。设计侧 D-1（响应 Action 派生规则钉死「去 Request 尾缀+Response」，#28/#31/#32 落地断言）、D-2（wsnt 命名空间 URI `docs.oasis-open.org/wsn/b-2` 入文与断言）、D-5（`action` 覆盖字段入 typedef + wire_fault 枚举 38 值与 §5 一一对齐）、D-6（锚词钉主锚词）、D-7（WWW-Authenticate 全参数）、D-9（Velocity 类型 tt:PTZSpeed + 可选 Timeout，#23/#24）、D-10（DaylightSavings 拼写，#47）、D-11（ReferenceToken maxLength=64 出处入文）、D-12（单事务 Connection 钉死 close，#16）随轮落地； CapabilityCategory 7 值全枚举（#40-46）、Category 多值（#46）、NetworkInterfaces 多实例（#5）、Profiles 多实例（#20）、Stop 双形态（#26/#27）、Filter（#29）、绝对 TerminationTime（#30）、DateTimeType 双值（#47-49）、前缀变体（#9）、Host 显式（#15）、IPv6 加强（#54）为枚举新增。
