# ONVIF（网络视频接口论坛，Open Network Video Interface Forum）设计契约

> 版本：v2.1.1（设计阶段）
> 日期：2026-09-01
> 状态：按《协议设计文档与用例文档需求文档 v1.3》完成独立重审（审查员 rr-onvif：行为面 138 点、confirmed findings 24 项 = 2 CRITICAL + 10 MAJOR + 12 MINOR），本版为修复轮产物：配套用例 32 条 → **95 条（57 正 + 38 负）**，待 rr-onvif 复验。记录见 §10。
> 配套文件：`docs/protocol-designs/67-onvif-testcase.md`、`trafficgen/test/protocol_pcap/cases/onvif.json`（当前 JSON 仅含注册前置占位，本版不写文件、不改代码）
> 规范基线：**ONVIF Core Specification Ver. 26.06**（2026-06，onvif.org 公开发布，按章节号引用，下称 Core Spec）；**ONVIF 服务 WSDL**（github.com/onvif/specs，devicemgmt/media/event/ptz 四份 WSDL 逐元素实测，命名空间/SOAPAction/操作形状以 WSDL 为准）；W3C **SOAP 1.2 Part 1**（Messaging Framework，信封结构）/**Part 2**（Adjuncts，HTTP 绑定与 Content-Type）；W3C **WS-Addressing 1.0**（2005-08 命名空间，MessageID/RelatesTo 关联）；OASIS **WSS UsernameToken Profile 1.0**（Core Spec §5.9.5 引用）；OASIS **WS-BaseNotification 1.3**（事件服务，wsnt 命名空间）。
> 修订记录：v2.1.0（2026-09-01，v1.3 重审修复轮）：rr-onvif 24 项 finding 修复——C-1/C-2（CRITICAL，WSDL 实测形状：GetProfiles 响应复数 Profiles+token 属性、GetNetworkInterfaces 用 tds: 本地元素）、C-3 pcap/NIC 双输出声明、C-4 并发会话翻案纳入、C-8 RST 不产生声明、C-9 405/415/400-Malformed 正例化（响应形态钉死为 fixture 决策）、C-11 多会话包数矛盾钉死、D-1 响应 Action 派生规则钉死（去 Request 尾缀+Response）、D-2 wsnt 命名空间 URI 入文、D-3 digest 引证 §4.2、D-4 删 §8.3.2 悬空引用、D-5 action 覆盖字段 + wire_fault 枚举 38 值一一对齐、D-6 主锚词钉死、D-7 WWW-Authenticate 全参数、D-8 Table 4 子码计数更正、D-9 Velocity=tt:PTZSpeed+可选 Timeout、D-10 DaylightSavings 拼写、D-11 ReferenceToken maxLength=64 出处、D-12 单事务 Connection 钉死；§7 负例表 11→38 行原子拆分、§9 ID 权威改用例 §2。v2.0.1/v2.0.0（2026-09-01）：v1.1 隔离审查轮（见 §10 历史条目）。

## 1. 范围、profile 和未注册边界

本版定义 ONVIF 客户端（NVR/视频管理软件/巡检工具）与设备（摄像头）之间的**明文 SOAP over HTTP 控制面**：SOAP 1.2 envelope（信封）逐字段编码、HTTP/1.1 载体（POST）、WS-Addressing 头（Action/MessageID/To/RelatesTo 事务关联）、WS-Security UsernameToken（不透明断言）、Device 服务（GetSystemDateAndTime/GetCapabilities/GetDeviceInformation/GetNetworkInterfaces）、Media 服务（GetProfiles/GetStreamUri/GetSnapshotUri）、PTZ 服务（ContinuousMove/Stop）、Events 服务（CreatePullPointSubscription/PullMessages PullPoint 轮询）、SOAP 1.2 Fault、HTTP 401 digest 挑战、IPv4/IPv6、多会话与多事务。

| profile（协议档案） | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `onvif_soap12_http`（主 profile） | TCP + HTTP/1.1 明文（端口 80） | SOAP 1.2 over HTTP（`application/soap+xml`）、上述四服务操作、WS-Addressing、UsernameToken 不透明、Fault、401 挑战 | 设备真实身份/能力值、认证成功、签名有效、媒体流可播放 |
| `onvif_ipv6_v1` | TCP + HTTP/1.1 明文 over IPv6 | 同 `onvif_soap12_http`，仅外层地址族不同 | 从 IPv4 地址静默推导 IPv6 |
| `onvif_https_boundary` | TLS/TCP（443） | 仅边界声明，不设语义用例 | 未解密 TLS 内声称看见 HTTP/SOAP/XML |
| `onvif_wsdiscovery_boundary` | UDP 3702 多播 | 仅边界声明：WS-Discovery（Core Spec §7 Probe/ProbeMatch）**本版不实现** | 把 UDP 多播发现当 HTTP 主链一部分 |

**载体与发现决策**：主链从 HTTP POST `GetSystemDateAndTime` 直接开始（现网客户端拿到设备地址后即直连服务端点，发现属可选前置）；WS-Discovery 的 UDP/3702 SOAP-over-UDP 多播（Core Spec §7）为独立载体形态，本版不实现、不臆造，显式声明为边界。**SOAP 版本钉死 1.2**：Core Spec §5.7 "the WSDL SOAP 1.2 bindings shall be used"、§5.8.2.1 "Server and client shall use SOAP 1.2 fault message handling"；SOAP 1.1 envelope 命名空间（`http://schemas.xmlsoap.org/soap/envelope/`）与 `text/xml` Content-Type 属线格式错误（负例 §7），不设 SOAP 1.1 兼容正例。

**未注册边界**：当前仓库没有注册 `onvif` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/onvif.json` 只保留一个不计入语义 ID 的注册前置占位 `onvif_neg_unregistered`（`expect_error=true`、`error_contains` 精确为 `unknown layer`）。占位的拒绝、0 包或空 PCAP 不得报告为 ONVIF 行为通过；注册后按本文 §9 与用例文档 §2 的同一顺序替换为语义用例。

**动态值不硬编码**：wsa:MessageID（`urn:uuid:` 形态）、Nonce（base64）、Created/CurrentTime/TerminationTime（dateTime）、digest Password、订阅地址（SubscriptionReference）为运行期或 fixture 值——断言用 `nonzero`、`same_as_packet`、`distinct_values` 与稳定字节前缀；Manufacturer/Model/ProfileToken/token 值等属预配置值，允许 fixture 显式给出（实现期以渲染器输出校准后钉死）。

**pcap/NIC 双输出契约**：pcap 与 `port_group`/NIC 两种输出路径使用同一份用例契约——同一组语义 ID、同一包数约定、同一断言集（fields/frames），不含输出路径专有断言；NIC 路径的抓包口差异不改变任何用例语义（与 64-cwmp/66-doh 同形）。

**证据等级声明**：命名空间 URI、SOAPAction URI、各操作请求/响应元素形状、访问类别（ACCESS CLASS）、错误码表、线示例均为 Core Spec Ver. 26.06 原文与 onvif/specs WSDL **逐字实测**；HTTP 头部交互细节（如 tshark 对 `application/soap+xml` 的内层解码行为）无专用 dissector（用例文档 §1 实测声明），断言以 `http.*` 实测字段 + frames hex 表达，公开资料缺处以"依据 Core Spec X + 假设，实现阶段 tshark 实证校准"标注。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[tcp, http, onvif]`（引擎自动补 `ip`；需要显式地址族时写 `[ip, tcp, http, onvif]` 或 IPv6 等价链）。HTTP 语义（POST 请求行/响应状态行/Content-Length/keep-alive）由 `http` 层承载，`onvif` 终结层在其上产出 SOAP 1.2 envelope 与事务序列——与 `cwmp`/`doh` 同款分层先例。

端口：HTTP 默认 80（Core Spec §4.1 "HTTP as the underlying transport mechanism"，规范未钉死专用端口；服务端点地址由 GetCapabilities 响应 XAddr 或配置给出）。本版 fixture 统一 `dst_port=80`；端口可被配置覆盖，planner 不得静默改写。

**固定偏移**：无 VLAN（虚拟局域网）、无 IP options（IP 选项）、无 TCP options 时，HTTP 起行起点为 IPv4 offset（偏移）54（Ethernet 14 + IPv4 20 + TCP 20）、IPv6 offset 74（14 + IPv6 40 + TCP 20）。**SOAP envelope 在 HTTP body 内，偏移不固定**——envelope 起点 = 54/74 + 该 fixture 固定 HTTP 头集合的字节长 + 2（CRLF 空行；头集合由配置钉死，偏移可预算）。因此 SOAP 断言以 `http.file_data`（body 内容）+ frames 的 body 起点偏移 hex 前缀表达，不以固定帧偏移表达。HTTP 消息边界由 Content-Length 界定，**TCP 分段边界不是 HTTP/SOAP 消息边界**。

## 3. 线格式编码（逐项标注出处）

### 3.1 HTTP 载体（Core Spec §5.8.2.1 示例、§5.8.2.4 Table 5；SOAP 1.2 Part 2 §4 HTTP 绑定）

**请求**（一切 ONVIF 服务请求均为 HTTP POST，body 为完整 SOAP 1.2 envelope）：

```text
POST /onvif/device_service HTTP/1.1
Host: 198.51.100.67
Content-Type: application/soap+xml; charset=utf-8
Content-Length: <len(envelope)>
Connection: keep-alive

<s:Envelope ...>...</s:Envelope>
```

**响应**（成功响应，Core Spec §5.8.2.1 示例原文 `CONTENT-TYPE: application/soap+xml; charset="utf-8"`）：

```text
HTTP/1.1 200 OK
Content-Type: application/soap+xml; charset=utf-8
Content-Length: <len(envelope)>

<s:Envelope ...>...</s:Envelope>
```

HTTP 头逐项规则：

| 头 | 规则 | 出处 |
|---|---|---|
| 请求行 | `POST <service-uri> HTTP/1.1`；service-uri 为服务端点路径（fixture 钉死，如 `/onvif/device_service`、`/onvif/media_service`） | Core Spec §4.1（HTTP 承载）；端点来自 GetCapabilities XAddr |
| `Content-Type` | 请求/响应均为 `application/soap+xml`，**必须带 `charset=utf-8`**（Core Spec §5.10.1 设备须支持 UTF-8；§5.8.2.1 示例带 charset） | SOAP 1.2 Part 2 §4.1.1；Core Spec §5.8.2.1 |
| `SOAPAction` 头 | **SOAP 1.2 不使用**：action 以 Content-Type `action="…"` 参数携带（可选）或由 body 操作名隐含；SOAPAction 头属 SOAP 1.1 遗留，本版不产生 | SOAP 1.2 Part 2 §4.1.1 |
| `Content-Length` | = envelope 渲染后字节数（十进制 ASCII） | HTTP/1.1 语义 |
| `Connection` | 多事务逐请求 `keep-alive`、末事务 `close`；**单事务会话钉死 `close`**（唯一事务即末事务，D-12） | 与 `http` 层缺省一致 + 本版钉死 |
| `WWW-Authenticate` | 401 挑战携带 `Digest realm="…" nonce="…" qop="auth" algorithm=MD5 opaque="…"`（**全参数 fixture 钉死**——Core Spec §5.9.1 示例含 algorithm 与 opaque，D-7） | Core Spec §5.9.1 |
| `Authorization` | 客户端补 digest 凭据后携带 | Core Spec §5.9.1 |

**HTTP 状态码规则**（Core Spec §5.8.2.4 Table 5 + §5.8.2.1 + §5.9.1）：200 = 承载 SOAP 响应（含 Fault——§5.8.2.1 示例 Fault 用 **500** + envelope；Fault 状态码钉死见 §3.6）；**400** = Malformed Request（无法开始解析 SOAP 时，无 SOAP body；与 §5.9.1 认证缺失 Fault 的 400 不同——后者带 SOAP envelope）；**401** = Requires Authorization（请求需认证而未携带凭据，digest 模式设备）；**405** = 方法非 POST/GET；**415** = 不支持的封装（媒体类型）。HTTP 200 不等于业务成功（body 可能是 Fault）。HTTP GET 本版不产生（快照/日志下载属媒体面资源 URI，本版不实现，声明为边界）。**非 2xx 错误响应形态（本版 fixture 决策，Table 5 仅钉状态码语义，无 RFC 强制）**：400-Malformed/405/415 与 401 挑战的响应 = 状态行 + `Content-Length: 0`，不携带 SOAP envelope 与 Content-Type（401 额外携带 WWW-Authenticate）；400 认证 Fault（§5.9.1）与 500 通用 Fault（§3.6）**带 envelope**。三者均为合法协议事件，用例各设正例（用例 §2 #12-14、#11、#37/#38）。

### 3.2 SOAP 1.2 envelope（W3C SOAP 1.2 Part 1 §5；Core Spec §5.8.2.1 示例）

```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
    <wsa:Action xmlns:wsa="http://www.w3.org/2005/08/addressing">
      http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime
    </wsa:Action>
    <wsa:MessageID xmlns:wsa="http://www.w3.org/2005/08/addressing">
      urn:uuid:67000000-0000-0000-0000-000000000001
    </wsa:MessageID>
  </s:Header>
  <s:Body>
    <tds:GetSystemDateAndTime xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>
```

结构规则（均出自 SOAP 1.2 Part 1 §5 与 Core Spec §5.3 Table 1/§9.10 示例）：

| 项 | 规则 |
|---|---|
| envelope 命名空间 | **钉死 `http://www.w3.org/2003/05/soap-envelope`**（Core Spec §5.3 Table 2 `soapenv`）；XML 前缀任意（规范原文 "These prefixes are not part of the standard and an implementation can use any prefix"），**命名空间 URI 不可变**——禁止只凭前缀字符串判断 |
| 结构 | `Envelope`（根）→ 可选 `Header` → 必需 `Body`；Header 在 Body 之前；Body 内为单个操作元素（document/literal wrapped，Core Spec §5.7 "shall use the style 'document'"） |
| XML 声明 | `<?xml version="1.0" encoding="UTF-8"?>`（Core Spec §9.10 系列示例全部携带） |
| 编码风格 | document/literal wrapped；**无 SOAP encoding**（`soap-enc` 不用于操作元素） |
| 操作元素 | 顶层元素 = 服务命名空间下的操作名（如 `tds:GetSystemDateAndTime`）；其子元素为参数，**同为服务命名空间 qualified、wire 上带服务前缀**（WSDL schema `elementFormDefault="qualified"`：参数元素与操作元素同属服务目标命名空间，wire 上均以服务前缀限定——如 `<tds:Category>`、`<trt:StreamSetup>`、`<trt:ProfileToken>`、`<tptz:Velocity>`、`<tev:Timeout>`；WSDL 实测，与用例文档用例 2/10/12/13/14 的带前缀断言一致） |
| 响应元素名 | 请求操作名 + `Response` 后缀（WSDL 实测：`GetSystemDateAndTimeResponse` 等） |
| 字符集 | UTF-8（Core Spec §5.10.1） |

### 3.3 WS-Addressing 头（Core Spec §5.3 Table 2 `wsa`、§9.10 示例、§9 "Both device and client shall support [WS-Addressing] for event services"；关联规则出自 WS-Addressing 1.0 Core）

命名空间钉死 `http://www.w3.org/2005/08/addressing`。Header 块逐项：

| 元素 | 方向 | 规则 |
|---|---|---|
| `wsa:Action` | 请求+响应 | 请求 = `<服务命名空间>/<操作名>`（WSDL soapAction 实测：`http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime` 等；事件服务示例带 PortType 段：`http://www.onvif.org/ver10/events/wsdl/PullPointSubscription/PullMessagesRequest`，Core Spec §9.10.5 原文）。响应 = 请求 Action **去尾缀 `Request`（若有）再补 `Response`**（§9.10.2/§9.10.6 示例形态；D-1 钉死：`…/GetSystemDateAndTime`→`…/GetSystemDateAndTimeResponse`、`…/PullPointSubscription/PullMessagesRequest`→`…/PullPointSubscription/PullMessagesResponse`、`…/EventPortType/CreatePullPointSubscriptionRequest`→`…/CreatePullPointSubscriptionResponse`——不是「尾部操作名替换」的歧义读法，用例 #28/#31/#32 断言响应 Action 落地）。**Fault 的 Action** 钉死 `http://www.w3.org/2005/08/addressing/soap/fault`（Core Spec §9.9 原文，事件服务；通用 Fault 沿用该 URI——依据 Core Spec §5.8.2 + 假设，实现期校准） |
| `wsa:MessageID` | 请求 | `urn:uuid:<UUID>` 形态；**事务关联标识**（详见 §5） |
| `wsa:RelatesTo` | 响应 | **值 = 对应请求的 `wsa:MessageID`**（WS-Addressing 1.0 Core request-response 关联规则；ONVIF 响应示例未强制展示但关联语义即此——依据 WS-Addressing 1.0 + Core Spec §9 引用，实现期以 fixture 渲染断言钉死） |
| `wsa:To` | 请求（可选） | 目标端点地址；PullMessages 请求携带订阅端点地址（Core Spec §9.10.5 示例原文 `<wsa:To>http://160.10.64.10/Subscription?Idx=0</wsa:To>`） |

**事务关联规则**：请求/响应对 = 同一 HTTP 请求/响应配对 + `RelatesTo`/`MessageID` 同值配对；不同事务的 MessageID 必须 distinct（同会话内不重复）。

### 3.4 WS-Security UsernameToken（Core Spec §5.9.1、§5.9.5；OASIS WSS UsernameToken Profile 1.0）

Header 内携带（secext 命名空间 `http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd`、utility 命名空间 `http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd`）：

```xml
<s:Header>
  <Security xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
    <UsernameToken>
      <Username>admin</Username>
      <Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">…base64…</Password>
      <Nonce EncodingType="…#Base64Binary">…base64…</Nonce>
      <Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2026-09-01T00:00:00Z</Created>
    </UsernameToken>
  </Security>
</s:Header>
```

规则（Core Spec §5.9.5 原文）：**客户端必须同时携带 nonce 与时间戳**（"A client shall use both nonce and timestamps"），设备必须拒绝缺二者之一的 UsernameToken（"The server shall reject any Username Token not using both nonce and creation timestamps"）——缺 Nonce/Created 进入负例 §7。digest 值 = Base64(SHA1(nonce + created + password))（WSS UsernameToken Profile 1.0 §4.2，D-3 引证更正）；**本生成器不验证摘要正确性，只断言结构、命名空间、元素存在与长度**（Password/Nonce 为 base64 不透明字节）。认证缺省路径：请求需认证服务（READ_SYSTEM 及以上，§3.5 表）而不携带任何凭据 → HTTP 401 + `WWW-Authenticate: Digest`（Core Spec §5.9.1；仅支持 UsernameToken 的设备回 HTTP 400 + Fault `env:Sender ter:NotAuthorized`，本版 fixture 取 digest 挑战形态为主、Fault 形态由 `onvif_soap_fault_response` 覆盖）。

### 3.5 各服务操作请求/响应形状（WSDL 逐元素实测 + Core Spec 章节引用）

服务命名空间（Core Spec §5.3 Table 1 + WSDL tns 实测）：

| 前缀 | 命名空间 URI | 服务 |
|---|---|---|
| `tds` | `http://www.onvif.org/ver10/device/wsdl` | Device Management |
| `trt` | `http://www.onvif.org/ver10/media/wsdl` | Media |
| `tev` | `http://www.onvif.org/ver10/events/wsdl` | Events |
| `tptz` | `http://www.onvif.org/ver20/ptz/wsdl` | PTZ（注意 ver20，WSDL tns 实测） |
| `tt` | `http://www.onvif.org/ver10/schema` | 数据类型 schema |
| `ter` | `http://www.onvif.org/ver10/error` | Fault 子码（§3.6） |
| `wsnt` | `http://docs.oasis-open.org/wsn/b-2` | WS-BaseNotification（D-2 实测钉死；CurrentTime/TerminationTime/NotificationMessage/TopicExpression） |

操作形状（请求参数/响应元素，`?`=可选；ACCESS CLASS 引用 Core Spec §5.9.4.3）：

| 操作（服务） | 请求参数 | 响应元素 | 访问类别 | 出处 |
|---|---|---|---|---|
| `GetSystemDateAndTime`（device） | 空 | `SystemDateAndTime`（tds: 包装元素）`{DateTimeType/DaylightSavings/TimeZone?/UTCDateTime?/LocalDateTime?}`（**载荷元素全部 tt:**——类型 tt:SystemDateTime 定义于 onvif.xsd targetNamespace=tt 且 qualified，RN-2 实测；DateTimeType: tt:SetDateTimeType NTP/Manual 双值；DaylightSavings 拼写按 schema，D-10）（设备必须提供 UTCDateTime，Core Spec §8.3.6 原文） | **PRE_AUTH**（免认证） | §8.3.6 + WSDL |
| `GetCapabilities`（device） | `Category?`（tt:CapabilityCategory，0..n） | `Capabilities{…}`（含各服务 `XAddr` 地址，§8.1.2.1 原文 "references to the addresses (XAddr) of the service"） | **PRE_AUTH** | §8.1.2.4 + WSDL |
| `GetDeviceInformation`（device） | 空 | `Manufacturer/Model/FirmwareVersion/SerialNumber/HardwareId`（均 xs:string，五元素全为必选——WSDL sequence 无 minOccurs=0） | **READ_SYSTEM**（需认证） | §8.3.1 + WSDL |
| `GetNetworkInterfaces`（device） | 空 | `NetworkInterfaces`（**tds: 本地元素**、maxOccurs unbounded，类型 tt:NetworkInterface——token 为 tt:DeviceEntity 继承属性；子元素含 `tt:Enabled` 等。C-2 WSDL 实测：响应形状无 `tt:InterfaceToken` 元素，该元素仅见于 SetNetworkInterfaces 等请求） | **READ_SYSTEM** | §8.2.10 + WSDL |
| `GetProfiles`（media） | 空 | `Profiles`（**复数响应元素**，tt:Profile 类型实例 0..n，每个 Profiles 元素自带 `token` 属性 + Name/VideoEncoderConfiguration 等子配置——C-1 WSDL 实测：不存在单数 Profile 响应元素） | READ_MEDIA（依据 Core Spec §5.9.4.3 + Media 服务规范公开条款，实现期校准） | WSDL 实测 |
| `GetStreamUri`（media） | `StreamSetup`（trt: 包装，必选；子元素 `tt:Stream`（枚举 RTP-Unicast/RTP-Multicast）/`tt:Transport`→`tt:Protocol`（onvif.xsd 类型元素，RN-1 实测））+ `ProfileToken`（tt:ReferenceToken，必选） | `MediaUri{Uri: anyURI, InvalidAfterConnect?: …}` | 同上 | WSDL 实测 |
| `GetSnapshotUri`（media） | `ProfileToken`（必选） | `MediaUri` | 同上 | WSDL 实测 |
| `ContinuousMove`（ptz） | `ProfileToken`（必选）+ `Velocity?`（**tt:PTZSpeed**，D-9 实测更正）+ `Timeout?`（xs:duration，可选） | 空 | 同上 | WSDL 实测 |
| `Stop`（ptz） | `ProfileToken` + `PanTilt? boolean` + `Zoom? boolean` | 空 | 同上 | WSDL 实测 |
| `CreatePullPointSubscription`（events） | `Filter?`（wsnt:FilterType）+ `InitialTerminationTime?`（AbsoluteOrRelativeTimeType，如 `PT1M`）+ `SubscriptionPolicy?` | `SubscriptionReference{wsa:Address}`（订阅端点）+ `wsnt:CurrentTime` + `wsnt:TerminationTime` | READ_MEDIA（Core Spec §9.1.1 ACCESS CLASS 原文） | §9.1.1 + WSDL |
| `PullMessages`（events） | `Timeout`（xs:duration，必选，如 `PT5S`）+ `MessageLimit`（xs:int，必选） | `CurrentTime` + `TerminationTime` + `wsnt:NotificationMessage`（0..n，超时形态为空列表——§9.1.2 原文 "shall respond with zero messages"）；NotificationMessage 子结构（fixture 带消息时）：`wsnt:Topic`（`Dialect` 属性，ConcreteSet dialect `http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet`）+ `wsnt:Message` 载荷内 `tt:SimpleItem`（`Name`/`Value` 属性）——WS-BaseNotification 1.3 TopicExpression/Message 结构 + Core Spec §9 章示例形态，实现期对 §9.10.5 示例逐字校准 | 同上 | §9.1.2 + WSDL |

**必选参数校验**：GetStreamUri 缺 StreamSetup/ProfileToken、PullMessages 缺 Timeout/MessageLimit 均为线格式错误（负例 §7 `onvif_neg_parameter`，对应 Table 4 `ter:InvalidArgs`"missing argument"）。

**wsa:To 事务交互**：PullMessages 请求的 `wsa:To` 必须 = 同会话 CreatePullPointSubscription 响应的 SubscriptionReference 地址（§9.10.5 示例）；GetStreamUri 请求的 ProfileToken 必须先经 GetProfiles 获得（事件编排顺序依赖，§4/§5）。

**流关联边界（显式声明）**：GetStreamUri/GetSnapshotUri 响应的 MediaUri（`rtsp://…`/HTTP 形态）**仅作为返回字段断言**（URI 存在、前缀形态），**本版不派生 RTSP/HLS/JPEG 媒体数据面**——媒体流属另一协议族的独立数据流，本生成器无 RTSP 终结层；流关联（控制流派生媒体流的主从生成关系）显式**不适用**，媒体 URI 只作响应字段存在性断言（理由：媒体数据面承载协议为 RTSP/RTP 而非 ONVIF，Core Spec §4.1 亦将流传输委派给 RTSP 等传输机制）。

### 3.6 SOAP 1.2 Fault（Core Spec §5.8.2.1 示例原文、§5.8.2.2 Table 4、§9.9）

Fault 是承载错误的**正常 SOAP 响应**（正例形态，非 planner error）。结构（§5.8.2.1 示例逐字段）：

```xml
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:ter="http://www.onvif.org/ver10/error">
  <s:Body>
    <s:Fault>
      <s:Code>
        <s:Value>env:Sender</s:Value>
        <s:Subcode><s:Value>ter:NotAuthorized</s:Value></s:Subcode>
      </s:Code>
      <s:Reason><s:Text xml:lang="en">Sender not Authorized</s:Text></s:Reason>
      <s:Node>…</s:Node><s:Role>…</s:Role><s:Detail>…</s:Detail>
    </s:Fault>
  </s:Body>
</s:Envelope>
```

| 项 | 规则 | 出处 |
|---|---|---|
| HTTP 状态 | **500**（§5.8.2.1 示例原文 `HTTP/1.1 500 Internal Server Error`；§9.9 "the HTTP error code shall be 500"）；仅支持 UsernameToken 设备的认证缺失 Fault 用 **400**（§5.9.1） | §5.8.2.1/§9.9/§5.9.1 |
| `Code/Value` | `env:VersionMismatch`/`env:MustUnderstand`/`env:DataEncodingUnknown`/`env:Sender`/`env:Receiver`（SOAP 1.2 Part 1 §7 值域，Table 4 全集） | Table 4 |
| `Code/Subcode/Value` | `ter:` 前缀 ONVIF 子码：`WellFormed`、`TagMismatch`、`Tag`、`Namespace`、`MissingAttr`、`ProhibAttr`、`InvalidArgs`、`InvalidArgVal`、`UnknownAction`、`OperationProhibited`、`NotAuthorized`（配 `env:Sender`）；`ActionNotSupported`、`Action`、`OutofMemory`、`CriticalError`（配 `env:Receiver`）——**Table 4 原文全量** | §5.8.2.2 Table 4 |
| `Reason/Text` | 携带 `xml:lang="en"`，文本与 Table 4 Fault Reason 列对应（normative） | §5.8.2.2 |
| Node/Role/Detail | 可选 | §5.8.2.1 |
| Fault 的 wsa:Action | `http://www.w3.org/2005/08/addressing/soap/fault` | §9.9 |

GetCapabilities 特有 Fault：`env:Receiver - ter:ActionNotSupported - ter:NoSuchService`（请求的能力类别不支持，§8.1.2.4 原文；**实现期须对 Core Spec §8.1.2.4 核实子码组合与 Reason 文本**，防两文档自洽偏离规范）。

> 注（实现期待核验）：上表 `Code/Value` 值域与 `ter:` 子码全集及配对关系，实现期须对 Core Spec §5.8.2.2 Table 4 **逐字核对**（本表为撰写期转录，防设计/用例两文档自洽但共同偏离规范）。

### 3.7 每消息长度公式

- **envelope 长度**：`L_env = len(xml_decl) + len(envelope_open + 全部 Header 块 + Body 渲染 + 闭合标签)`——XML 无固定头，长度 = 渲染器逐元素序列化字节计数；fixture 层面 `Content-Length` 必须精确等于渲染后字节数，实现期由渲染器计数并与断言值钉死（实现前本文不硬编码具体字节数，防臆造；xml_decl 标准形态 38 字节）。
- **HTTP 消息总长**：`L_http = 请求行/状态行 + 头集合 + CRLF 空行(2) + L_env`；`Content-Length = L_env`（不含头）。
- **帧长公式**：`frame_len = 14(Eth) + 20/40(IP) + 20(TCP) + L_http`。
- **跨 MSS 分段**：承载 HTTP 消息的 TCP 段数 = `ceil((请求 L_http) / MSS)` 与 `ceil((响应 L_http) / MSS)` 分别上取整（`tcp` 层 MSS 参数控制，默认 1460）；**分段边界不是 SOAP 消息边界**，断言须按 `tcp.stream` 重组。
- **大响应上界**：GetCapabilities 响应含全部服务 XAddr 与能力结构，典型为 1–4 KB；envelope 无协议级上界（受 TCP/内存约束），生成器按 fixture 配置渲染、不做未限定分配。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性声明**：本引擎对 ONVIF 采用**声明式脚本化回放**——配置是剧本（sessions[]/events[] 逐条声明），引擎是回放者，按序产出帧；"事件驱动"一词不用于定性整体行为，仅用于两处反应性成分：①自动应答（渲染请求帧后自动补对应响应帧，内容由事件的 `response` 子映射声明）；②连接边界（事件序列中源端口切换触发新 TCP 连接）。

| 现网场景 | 事务交互 | 驱动顺序 | 对应用例 |
|---|---|---|---|
| ① 客户端接入首链（最常见：NVR/客户端发现地址后时钟同步→能力探测） | GetSystemDateAndTime（PRE_AUTH）→GetCapabilities（PRE_AUTH，取各服务 XAddr） | 客户端驱动全程；keep-alive 同连接多事务 | `onvif_ipv4_get_system_date_and_time`、`onvif_device_get_capabilities`、`onvif_http_keepalive_multi_transaction` |
| ② 认证后读设备信息（现网第二个动作） | 无凭据请求 GetDeviceInformation→401 挑战→带 UsernameToken（或 HTTP digest）重请求→200 | 客户端驱动 | `onvif_http_401_digest_challenge`、`onvif_ws_security_usernametoken`、`onvif_device_get_device_information`、`onvif_device_get_network_interfaces` |
| ③ 媒体取流准备（客户端拿流地址） | GetProfiles→取 profile token→GetStreamUri(StreamSetup+ProfileToken)→MediaUri（RTSP URL 仅返回字段） | **事务交互**：GetStreamUri 依赖 GetProfiles 先返回 token；事件编排显式声明顺序 | `onvif_media_get_profiles`、`onvif_media_get_stream_uri`、`onvif_media_get_snapshot_uri` |
| ④ PTZ 云台控制（操作台转动镜头） | ContinuousMove(ProfileToken+Velocity)→Stop(ProfileToken) | 两事务有先后（Move 先于 Stop），事件编排 | `onvif_ptz_continuous_move_stop` |
| ⑤ 事件订阅轮询（告警/移动侦测拉取） | CreatePullPointSubscription→SubscriptionReference（订阅端点）→PullMessages(Timeout+MessageLimit)→NotificationMessage（或超时零消息）→重复 Pull | **事务交互**：PullMessages 的 wsa:To 依赖 Create 响应的订阅地址 | `onvif_events_create_pullpoint_subscription`、`onvif_events_pull_messages` |
| ⑥ 设备错误路径（越权/能力类别不支持） | 无凭据请求需认证操作→HTTP 400 + Fault `env:Sender/ter:NotAuthorized`（§5.9.1 认证路径，仅 UsernameToken 模式设备）；请求不支持的能力类别→HTTP 500 + Fault `env:Receiver/ter:ActionNotSupported/ter:NoSuchService`（§8.1.2.4）——两种状态码形态不混用 | 客户端驱动 | `onvif_soap_fault_response`、`onvif_capabilities_no_such_service_fault` |

**五层覆盖逐层结论**：功能层——四服务 11 个操作全部正例 + envelope/WS-Addressing/UsernameToken 编码规则 + Fault + 401 挑战；错误分支逐类负例（§7 每行 ≥1 条）。性能层——大 GetCapabilities 响应跨 MSS 分段重组（`onvif_mss_large_capabilities`）、长 ProfileToken/MessageID 边界。数据场景层——操作参数值域（Category 枚举、StreamSetup、Timeout duration、MessageLimit int）、访问类别边界（PRE_AUTH vs READ_SYSTEM）、空 NotificationMessage 列表（超时零消息为合法形态）、MessageID distinct。地址与流层——IPv4/IPv6 独立 fixture、单流基线、多会话双四元组；**流关联显式不适用**（§3.5 边界声明：媒体 URI 仅返回字段，不派生 RTSP 数据面）；**多流（会话内部并发流）显式不适用**：HTTP/1.1 一个连接内请求/响应严格配对、无 pipelining，与 DOH 同口径。**并发会话纳入覆盖**（v2.1 翻案，cwmp⑦/doh #27 同判例）：HTTP/1.1「单连接串行」约束的是单个会话内部的事务交替，不约束生成器级多设备并发——`onvif_concurrent_sessions` 双客户端四元组交错回放，断言 MessageID/订阅上下文互不串用。业务层——接入首链、认证读信息、取流准备、PTZ、事件轮询均为现网日常，优先于教科书全操作遍历。

## 5. 消息/事务模型与状态机

**无状态服务模型**：ONVIF 是**无状态 SOAP 服务**——没有"登录会话"，认证按请求逐笔携带（UsernameToken 在每笔需认证请求的 Header 内，或 HTTP digest 逐请求）；连接仅是 HTTP keep-alive 复用，服务端不依赖连接状态。**事务定义**：一笔事务 = 同一 HTTP 请求/响应对（请求 body 操作元素 ↔ 响应 body `<操作>Response` 元素或 Fault）；**事务关联标识 = wsa:MessageID → wsa:RelatesTo**（§3.3）。**多事务** = 一个 TCP 连接内多笔事务按序执行（keep-alive），每笔独立 MessageID、请求/响应严格交替；**事务交互**（后序依赖前序返回值）：GetStreamUri 的 ProfileToken ← GetProfiles 响应；PullMessages 的 wsa:To ← CreatePullPointSubscription 响应的 SubscriptionReference——配置以 `same_as_response:<事件序号>` 引用声明（§6），validator 校验引用闭环。

连接生命周期状态机（每事件编排会话一份；SOAP 层无会话状态）：

| 状态 | 允许事件 | 必须保持 |
|---|---|---|
| `ConnectPending` | TCP 三次握手完成 | 握手后首帧是 HTTP POST（含完整 envelope） |
| `RequestSent` | 渲染请求帧（事件 kind=request） | Content-Type=application/soap+xml; charset=utf-8；Content-Length=渲染字节数；需认证事务携带 UsernameToken（nonce+created 齐）或已通过 401 往返 |
| `ResponsePending` | 自动应答补响应帧 | 响应 body = `<操作>Response` 或 Fault；wsa:RelatesTo=请求 MessageID；Content-Length 自洽 |
| `KeepAlive`（多事务） | 下一笔请求 | 请求/响应严格交替（无 pipelining）；每笔 MessageID distinct |
| `Terminating` | FIN 挥手 | 全部事务完成后才挥手 |
| `Closed` | TCP FIN | 关闭后不得产生新业务帧 |

**异常中断声明**：本协议挥手统一 FIN 四帧正常序列，`onvif` 层不产生 RST（传输层注入面非本协议语义，与 64-cwmp 同形）；生成器不在会话中途注入 RST，异常中断场景不设用例、由传输层语义承载。

**错误与重试语义**：HTTP 401/400/405/415 与 SOAP Fault 都是**合法协议事件**（正例形态）；生成器不模拟客户端认证重试算法（401 后是否重发由事件序列显式声明——`onvif_http_401_digest_challenge` 用例声明"无凭据请求→401→带凭据重请求→200"三帧序列，引擎照剧本回放，不自动补重试）。配置、线格式、长度或关联错误进入负例（§7），与合法错误响应严格区分。

**自动派生规则**（引擎自动补出的帧，逐条列出触发条件与内容）：
- 每个请求事件渲染完成后，引擎立即自动补对应响应帧（自动应答）：响应 = 状态行 + 头 + envelope（`<操作>Response` 元素按事件 `response` 子映射渲染；`wsa:RelatesTo` 自动回填本事务请求的 MessageID；响应 `wsa:Action` 自动派生 = 请求 Action 去尾缀 `Request`（若有）再补 `Response`，D-1 规则）。无 `response` 子映射时视为配置错（负例锚词 `response`）。
- TCP 握手/挥手由 `tcp` 层承载（连接边界反应性成分：事件序列中源端口变化触发新连接，多会话展开）。
- 除上述外不自动生成任何协议帧（不自动补 Unsubscribe、不自动补 401 重试、不自动派生媒体流）。

## 6. 配置 typedef（JSON 形状示例，非 Go 代码）

```json
{
  "layers": [{"tcp": {}}, {"http": {}}, {"onvif": {}}],
  "src_ip": "192.0.2.67", "dst_ip": "198.51.100.67",
  "src_port": 4067, "dst_port": 80,
  "onvif": {
    "profile": "onvif_soap12_http",
    "soap_version": "1.2",
    "charset": "utf-8",
    "sessions": [
      {
        "src_port": 4067, "dst_port": 80,
        "events": [
          {"kind": "request", "service": "device", "operation": "GetSystemDateAndTime",
           "uri": "/onvif/device_service", "message_id": "auto",
           "response": {"http_status": 200,
             "system_date_and_time": {"date_time_type": "NTP", "daylight_savings": false,
               "utc_date_time": "2026-09-01T00:00:00Z", "time_zone": "CST-8"}}},
          {"kind": "request", "service": "device", "operation": "GetCapabilities",
           "uri": "/onvif/device_service", "message_id": "auto",
           "parameters": {"category": ["All"]},
           "response": {"http_status": 200,
             "capabilities": {
               "media": {"x_addr": "http://198.51.100.67/onvif/media_service"},
               "events": {"x_addr": "http://198.51.100.67/onvif/event_service"},
               "ptz": {"x_addr": "http://198.51.100.67/onvif/ptz_service"}}}},
          {"kind": "request", "service": "device", "operation": "GetDeviceInformation",
           "uri": "/onvif/device_service", "message_id": "auto",
           "auth": {"username": "admin", "password": "changeme", "digest": true},
           "response": {"http_status": 200, "manufacturer": "Example", "model": "IPC-67",
             "firmware_version": "1.0.0", "serial_number": "SN0000067", "hardware_id": "HW-67"}}
        ]
      },
      {
        "src_port": 4068, "dst_port": 80,
        "events": [
          {"kind": "request", "service": "media", "operation": "GetProfiles",
           "uri": "/onvif/media_service", "message_id": "auto",
           "response": {"http_status": 200, "profiles": [
             {"token": "profile_1", "name": "mainStream",
              "video_encoder": {"encoding": "H264", "width": 1920, "height": 1080, "fps": 25}}]}},
          {"kind": "request", "service": "media", "operation": "GetStreamUri",
           "uri": "/onvif/media_service", "message_id": "auto",
           "parameters": {"stream_setup": {"stream": "RTP-Unicast", "protocol": "RTSP"},
                          "profile_token": "same_as_response:0.profiles[0].token"},
           "response": {"http_status": 200,
             "media_uri": "rtsp://198.51.100.67:554/profile_1/stream1"}}
        ]
      }
    ],
    "wire_fault": ""
  }
}
```

形状要点：`sessions[]` = 统一术语的**事件编排会话**（每个自带四元组与事件序列，多会话展开按序整块回放，第二会话包号起点 = 前会话总包数 + 1）；`events[]` = 会话的**事件序列**，元素为一笔 ONVIF 事务（`kind: request`）；`service`/`operation` 决定命名空间与 body 元素（§3.5 表）；`uri` 为服务端点路径；`message_id` 取 `auto`（运行期分配 `urn:uuid:`，禁止正例固化）或 `same_as_response:<n>` 引用；`action` 为可选覆盖字段（缺省按 §3.3 WSDL soapAction 自动派生，D-5 注入口——`onvif_neg_action_mismatch`/`onvif_neg_action_suffix` 由此注入）；`auth` 声明 UsernameToken（digest 值由引擎按 WSS §4.2 计算，nonce 运行期生成）；`response` 声明自动应答内容（状态码 + 响应字段）；参数值 `"same_as_response:0.profiles[0].token"` 为**事务交互引用**（GetStreamUri 的 token ← 事件 0 响应），validator 必须校验引用闭环（引用不存在 = 关联错，负例锚词 `correlation`）；`wire_fault` 仅负例注入口，**取值 38 个、与 §7 表/用例文档 §5 的 38 个负例一一对应（v2.1 原子拆分）**：`soap_envelope_ns`/`soap_truncated`/`soap_body_missing`/`soap_header_order`/`content_type`/`charset_missing`/`charset_wrong`/`action_mismatch`/`action_suffix`/`addressing_action`/`addressing_message_id`/`addressing_relates`/`addressing_ns`/`operation_unknown`/`operation_ns`/`service_unknown`/`parameter_stream_setup`/`parameter_profile_token`/`parameter_timeout`/`parameter_message_limit`/`parameter_duration`/`auth_missing`/`token_nonce`/`token_created`/`carrier_layer`/`carrier_port`/`carrier_wsdiscovery`/`fault_code`/`fault_reason`/`fault_value`/`fault_subcode`/`length_truncation`/`length_content_length`/`subscription_source`/`subscription_cross_session`/`token_range`/`message_limit_range`/`wsnt_ns`，不得成为线上字段。并发会话（`concurrent: true`）纳入覆盖（v2.1 翻案，§4）：双客户端四元组交错回放，单会话内部仍请求/响应严格交替。

## 7. 错误处理（负例锚词表）

以下输入必须由 planner/validator 拒绝并传播为 task error（任务错误），不得产出成功 PCAP、`completed/0 packet` 或仅 TCP/HTTP 外壳的假成功。锚词（anchor word）为 `error_contains` 断言字面值，主锚词钉死（备选供实现期校准，D-6），与用例文档 §5 一一对应：

| 负例 ID | `wire_fault` 注入口（v2.1，38 值） | 故障输入（方向） | `error_contains` 主锚词（备选） | 依据 |
|---|---|---|---|---|
| `onvif_neg_soap_envelope_ns` | `soap_envelope_ns` | envelope 命名空间写为 SOAP 1.1（schemas.xmlsoap.org/soap/envelope/） | `envelope`（namespace/soap） | SOAP 1.2 钉死（设计§1/§3.2） |
| `onvif_neg_soap_truncated` | `soap_truncated` | XML 截断：envelope/操作元素未闭合 | `xml`（truncate/envelope） | 设计§3.2/§7 |
| `onvif_neg_soap_body_missing` | `soap_body_missing` | s:Body 缺失（仅 Header） | `body`（envelope/soap） | SOAP 1.2 Part 1 §5（Body 必需） |
| `onvif_neg_soap_header_order` | `soap_header_order` | s:Header 位于 s:Body 之后 | `header`（order/envelope） | SOAP 1.2 Part 1 §5（Header 先于 Body） |
| `onvif_neg_content_type` | `content_type` | Content-Type 为 text/xml（SOAP 1.1 形态） | `content-type`（media） | 设计§3.1（钉死 soap+xml） |
| `onvif_neg_charset_missing` | `charset_missing` | Content-Type 缺 charset=utf-8 参数 | `charset`（content-type） | Core Spec §5.10.1 |
| `onvif_neg_charset_wrong` | `charset_wrong` | charset=gbk（非 UTF-8） | `charset`（encoding） | Core Spec §5.10.1 |
| `onvif_neg_action_mismatch` | `action_mismatch` | 事件声明 action 与 body 操作不一致（action=GetCapabilities 而 body=GetProfiles） | `action`（operation） | 设计§3.3 |
| `onvif_neg_action_suffix` | `action_suffix` | 事件声明请求 Action 尾缀已是 Response（违反去 Request 尾缀+Response 派生规则） | `action`（response） | 设计§3.3 D-1 规则 |
| `onvif_neg_addressing_action` | `addressing_action` | 请求缺 wsa:Action | `addressing`（action） | WS-Addressing+设计§3.3 |
| `onvif_neg_addressing_message_id` | `addressing_message_id` | 请求缺 wsa:MessageID | `message`（addressing） | WS-Addressing 1.0 |
| `onvif_neg_addressing_relates` | `addressing_relates` | 响应 RelatesTo ≠ 请求 MessageID | `relates`（correlation） | WS-Addressing 1.0 request-response |
| `onvif_neg_addressing_ns` | `addressing_ns` | wsa 命名空间非 2005/08/addressing | `addressing`（namespace） | Core Spec §5.3 Table 2 |
| `onvif_neg_operation_unknown` | `operation_unknown` | 未知操作名（如 GetFooBar） | `operation`（unknown） | WSDL 实测（操作全集外） |
| `onvif_neg_operation_ns` | `operation_ns` | media 操作声明在 device 服务下（服务/命名空间不匹配） | `namespace`（operation） | WSDL 实测（tns 实测） |
| `onvif_neg_service_unknown` | `service_unknown` | service 声明不在四服务内（如 imaging） | `service`（unknown） | 设计§1/§3.5（本版四服务） |
| `onvif_neg_parameter_stream_setup` | `parameter_stream_setup` | GetStreamUri 缺 StreamSetup 必选参数 | `parameter`（missing） | WSDL 实测 |
| `onvif_neg_parameter_profile_token` | `parameter_profile_token` | GetStreamUri 缺 ProfileToken 必选参数 | `parameter`（missing） | WSDL 实测 |
| `onvif_neg_parameter_timeout` | `parameter_timeout` | PullMessages 缺 Timeout 必选参数 | `parameter`（missing） | WSDL 实测 |
| `onvif_neg_parameter_message_limit` | `parameter_message_limit` | PullMessages 缺 MessageLimit 必选参数 | `parameter`（missing） | WSDL 实测 |
| `onvif_neg_parameter_duration` | `parameter_duration` | Timeout 声明非 duration 文本（如 5s/now） | `parameter`（duration） | xs:duration |
| `onvif_neg_auth_missing` | `auth_missing` | READ_SYSTEM+ 事务无 auth 声明且无 401 往返声明 | `auth`（credential） | Core Spec §5.9 |
| `onvif_neg_token_nonce` | `token_nonce` | UsernameToken 缺 Nonce | `nonce`（token） | Core Spec §5.9.5（nonce+created 强制） |
| `onvif_neg_token_created` | `token_created` | UsernameToken 缺 Created | `created`（token） | Core Spec §5.9.5 |
| `onvif_neg_carrier_layer` | `carrier_layer` | 层链缺 http（tcp→onvif 直连） | `layer`（carrier） | 设计§2 |
| `onvif_neg_carrier_port` | `carrier_port` | 端口/载体矛盾（如 profile 声明明文 HTTP 配 443） | `port`（carrier） | 设计§2 |
| `onvif_neg_carrier_wsdiscovery` | `carrier_wsdiscovery` | WS-Discovery UDP 载体误配为主链 | `carrier`（discovery） | 设计§1 边界 |
| `onvif_neg_fault_code` | `fault_code` | Fault 响应缺 s:Code | `fault`（code） | SOAP 1.2 §5.4 |
| `onvif_neg_fault_reason` | `fault_reason` | Fault 响应缺 s:Reason | `reason`（fault） | SOAP 1.2 §5.4 |
| `onvif_neg_fault_value` | `fault_value` | Code/Value 不在 SOAP 1.2 值域（如 env:Foo） | `code`（value） | SOAP 1.2 Part 1 §7 |
| `onvif_neg_fault_subcode` | `fault_subcode` | Subcode 值缺 ter: 前缀/命名空间（裸 NotAuthorized） | `subcode`（namespace） | Core Spec Table 4 |
| `onvif_neg_length_truncation` | `length_truncation` | envelope 渲染截断（闭合缺失致字节数与声明不符） | `length`（truncate） | 设计§3.7 |
| `onvif_neg_length_content_length` | `length_content_length` | Content-Length ≠ 渲染字节数 | `content-length`（length） | HTTP/1.1 语义 |
| `onvif_neg_subscription_source` | `subscription_source` | PullMessages wsa:To 的 same_as_response 指向非 Create 事件或不存在事件 | `subscription`（reference） | 设计§3.5 |
| `onvif_neg_subscription_cross_session` | `subscription_cross_session` | 订阅引用跨会话（引用他会话事件） | `correlation`（session） | 设计§5 |
| `onvif_neg_token_range` | `token_range` | ProfileToken 声明 65 字符（maxLength 64 +1 越界） | `token`（length） | common.xsd maxLength=64+需求 v1.3 边界相邻值 |
| `onvif_neg_message_limit_range` | `message_limit_range` | MessageLimit 声明 2147483648（xs:int 满值 +1 越界） | `limit`（range） | xs:int+需求 v1.3 边界相邻值 |
| `onvif_neg_wsnt_ns` | `wsnt_ns` | 事件操作 wsnt 命名空间 URI 错（非 docs.oasis-open.org/wsn/b-2） | `wsnt`（namespace） | WS-BaseNotification b-2（D-2 实测） |

**不得误报为 planner error 的合法协议事件**：HTTP 401 挑战本身、HTTP 400/405/415 错误响应（Table 5）、SOAP Fault 响应本身（Table 4 全部子码）、PullMessages 超时零消息响应、GetCapabilities 的 `ter:NoSuchService` Fault、PRE_AUTH 操作不带凭据（GetSystemDateAndTime/GetCapabilities 免认证是规范行为）、MessageID 重复出现于不同会话（会话间独立空间）。只有配置、线格式、长度或关联错误进入负例（v2.1 起 400-Malformed/405/415 已正例化为用例 #12-14，错误响应形态钉死见 §3.1）。

## 8. 边界

- **大响应跨 MSS**：GetCapabilities 响应含全部服务 XAddr + 能力结构（fixture 可配置多服务条目），MSS 压小使响应跨 ≥2 个 TCP 分段；必须按 Content-Length/`tcp.stream` 重组后再断言 envelope 完整（`onvif_mss_large_capabilities`）；分段边界不是 SOAP 消息边界。
- **长引用值**：tt:ReferenceToken（ProfileToken）与 `urn:uuid:` MessageID 为字符串——tt:ReferenceToken 上界 = **maxLength 64**（onvif/specs `common.xsd` 实测，D-11 出处）——fixture 取 63（-1 邻位）/64（满值），65 为越界负例；MessageID 全 UUID 36 字符形态；二者均只断言存在/长度/关联，不硬编码运行期值。
- **空响应形态**：PullMessages 超时响应 NotificationMessage 列表为空（合法，§9.1.2）；ContinuousMove/Stop 响应 body 为空 `<操作>Response` 元素（合法，WSDL 空 sequence）。
- **访问类别边界**：PRE_AUTH 操作（GetSystemDateAndTime/GetCapabilities）无凭据直接 200（正例 1/2）；READ_SYSTEM 操作无凭据 401（digest 挑战，正例 7）或 400 + Fault `ter:NotAuthorized`（仅 UsernameToken 模式设备，正例 15，§5.9.1）——两类边界各有断言。
- **v4/v6**：独立 fixture（192.0.2.67→198.51.100.67 与 2001:db8::67→2001:db8::100:67），同一逻辑 envelope 字节必须一致，仅外层 IP 头与偏移（54/74）不同；不得从 IPv4 推导 IPv6。
- **多会话**：≥2 个独立四元组，MessageID 空间、订阅上下文、重组缓存互不串用；会话间包序按多会话展开（第二会话握手包号 = 前会话总包数 + 1）。
- **keep-alive 多事务**：单 `tcp.stream` 承载 ≥3 笔事务，请求/响应严格交替、`Connection: keep-alive`、末事务 `close`；不产生 pipelining。
- 不得产生回绕长度或超量分配（envelope 长度按渲染计数，无未限定 buffer）。

## 9. 原子 ID 与完成定义

**ID 权威（v1.3 行为面全枚举）**：语义用例 ID 清单以**用例文档 §2 为唯一权威**（v2.1 起按可测试行为面全枚举扩量：**95 条 = 57 正例 + 38 负例**，对应 rr-onvif 枚举 138 行为面点）；本节不再维护 ID 逐条表（v2.0.x 的 32 ID 表见 git 历史）。设计、用例文档与未来 `onvif.json` 使用同一组唯一 ID 与顺序。当前 JSON 另有不计入的 `onvif_neg_unregistered` 占位。正例面：四服务 11 操作逐操作、envelope/wsa/WSS 编码规则逐条、HTTP Table 5 状态码 400/401/405/415 合法事件正例化、SOAP Fault 400/500 两形态 + 全形、CapabilityCategory 7 值全枚举、duration/int/ReferenceToken 边界（含邻位）、前缀变体、Host 显式、v4/v6、多会话、并发会话、MSS 大响应。负例面：§7 表 38 行逐错误分支。

**Table 5 状态码用例口径（v2.1）**：200/401/400-Malformed/405/415/400 认证 Fault/500 通用 Fault 全部有正例断言（用例 §2 #11-14、#37、#38，其余 200）——Table 5 五个状态码无一停留在边界声明。

完成定义：注册 `tcp→http→onvif` 层链；逐字段生成并验证 §3 的 HTTP 头、SOAP 1.2 envelope、WS-Addressing、UsernameToken 与四服务 11 操作的请求/响应；自动应答、多事务 keep-alive、多会话展开、IPv4/IPv6、MSS 分段与边界均可观测；95 个语义 ID（57 正 + 38 负）正负断言与错误传播完成；未注册阶段只接受 `unknown layer` 占位。**流关联边界**：媒体流 URI 仅作 GetStreamUri/GetSnapshotUri 响应字段断言，不实现 RTSP 数据面（§3.5 显式声明，实现期不得"顺手"派生）。

## 10. 修订记录

- v1.0.0（2026-08-20）：旧稿首版（14 正 + 6 负：含 discovery_probe/tls_opaque_carrier/pcap_nic_consistency 等 ID）。
- v2.1.1（2026-09-01，RN 复验轮收尾）：rr-onvif 复验 24 项中 22/24 CLOSED，新发现 RN-1（CRITICAL：GetStreamUri StreamSetup 子元素按 onvif.xsd 实测为 tt: 前缀、StreamType 枚举为连字符 RTP-Unicast——`RTP_Unicast` 非 schema 枚举值）、RN-2（CRITICAL：GetSystemDateAndTime 载荷元素全部 tt: 命名空间——包装元素 tds:、类型 tt:SystemDateTime 定义于 onvif.xsd targetNamespace=tt 且 qualified，五处 tds:→tt:）、RN-3（MINOR：#12 措辞改纯响应侧编排表述）+ D-3 残留一处（§6 digest 引证 WSS §3.1→§4.2）；四处修复后 rr-onvif 关单复验判定 **clean**（confirmed findings = 0，结构回归 95 = 57 正 + 38 负不变）。
- v2.1.0（2026-09-01，v1.3 重审修复轮）：rr-onvif 按《需求文档 v1.3》独立重审（行为面 138 点、24 confirmed findings = 2C/10M/12M）后全量修复：①C-1（CRITICAL）§3.5 GetProfiles 响应形状按 WSDL 实测改为复数 `Profiles`（tt:Profile 实例带 token 属性），删除单数 Profile 元素口径；②C-2（CRITICAL）GetNetworkInterfaces 响应改为 `tds:` 本地元素 + token 属性 + `tt:Enabled`，删除臆造的 `tt:InterfaceToken`；③C-3 §1 补 pcap/NIC 双输出契约声明；④C-4 并发会话翻案纳入覆盖（§4/§6，`onvif_concurrent_sessions`）；⑤C-8 §5 补 RST 不产生声明（FIN 统一挥手，cwmp 同形）；⑥C-9 §3.1 405/415/400-Malformed 正例化，非 2xx 响应形态钉死为本版 fixture 决策（状态行+`Content-Length: 0`、无 envelope；Table 5 仅钉状态码语义）；⑦D-1 §3.3/§5 响应 Action 派生规则钉死「去尾缀 Request+补 Response」；⑧D-2 §3.5 补 wsnt 命名空间 URI `http://docs.oasis-open.org/wsn/b-2`；⑨D-3 digest 公式引证 WSS §4.2；⑩D-4 §3.1 删除 §8.3.2 悬空引用、GET 场景改边界声明；⑪D-5 §6 事件 typedef 补 `action` 覆盖字段（neg_action 注入口）、`wire_fault` 枚举显式 38 值与 §7/用例 §5 一一对齐；⑫D-6 §7 锚词改「主锚词（备选）」钉死；⑬D-7 §3.1 WWW-Authenticate 全参数（algorithm/opaque）；⑭D-9 §3.5 ContinuousMove Velocity 类型更正 tt:PTZSpeed + 补可选 Timeout（xs:duration）；⑮D-10 DaylightSavings 拼写实测更正；⑯D-11 §8 ReferenceToken 上界补 common.xsd maxLength=64 出处；⑰D-12 §3.1 单事务 Connection 钉死 close；⑱§7 负例表 11→38 行原子拆分；⑲§9 ID 权威改用例文档 §2、总量 95 条（57 正 + 38 负）；⑳D-8 修订记录 v2.0.0 条目「Table 4 全量 16 子码」更正为 15 子码（Table 4 实测 15 子码 + 3 个无子码 fault code）。
- v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写，取代 2026-08-20 旧稿（旧稿见 git 历史）。对照 ONVIF Core Specification Ver. 26.06 全文与 onvif/specs WSDL（devicemgmt/media/event/ptz 四份逐元素）实测校准：①载体收敛为明文 HTTP/SOAP 1.2 主 profile，WS-Discovery（UDP 3702）与 HTTPS/TLS 降为 §1 未注册边界声明（旧稿含 discovery_probe/tls 用例，删除）；②SOAP 版本钉死 1.2（Core Spec §5.7 WSDL SOAP 1.2 binding SHALL、§5.8.2.1 SOAP 1.2 fault handling），旧稿 SOAPAction 头口径修正为 SOAP 1.2 的 Content-Type `action` 参数（SOAPAction 头属 1.1 遗留，不产生）；③规范章节级出处入文（§5.3 Table 1/2 命名空间、§5.7 binding、§5.8.2.1 Fault 示例原文、§5.8.2.2 Table 4 全量 15 子码、§5.8.2.4 Table 5 HTTP 错误、§5.9.1 401/400 认证路径、§5.9.5 nonce+created 强制、§8.3.6 UTCDateTime、§9.1.1/§9.1.2 PullPoint、§9.9 fault action、§9.10 逐字节线示例）；④用例按 v1.1 原子原则从 20 条重排为 31 条（20 正 + 11 负）——每服务操作各一例、envelope/action/addressing/auth 编码规则各一例、401 挑战、Fault、多事务、多会话、MSS、长 token 各一例，负例 11 类锚词逐条；⑤流关联显式声明不适用（媒体 URI 仅返回字段，不派生 RTSP 数据面）；⑥tshark 3.6.14 实测无 `onvif.*`/`soap.*` 字段（`-G fields`/`-G protocols` 核验），断言基线定为 `http.*` 实测字段 + frames hex 前缀（与 cwmp 同款）。
- v2.0.1（2026-09-01）：按独立隔离审查 9 项问题清单修复（2 MAJOR / 5 MINOR / 2 待核验注）：**O01**（MAJOR）§3.2 操作元素参数口径修正——参数为服务命名空间 qualified、wire 上带服务前缀（`elementFormDefault="qualified"`，以用例 2/10/12/13/14 带前缀断言为准）；**O02**（MAJOR）认证缺失 Fault（HTTP 400，§5.9.1）与通用 Fault（HTTP 500，§5.8.2.1/§9.9）两种状态码形态拆分——用例 15 改为 400 认证路径，新增用例 21 `onvif_capabilities_no_such_service_fault` 覆盖 500 通用形态（GetCapabilities 不支持类别），总数 31→32（21 正 + 11 负），§4⑥/§8 同步；**O03** §9 显式声明 Table 5 状态码用例口径——200/400/401/500 有正例（7/15/21 等），405/415 为边界声明不设独立用例；**O04** §3.5 PullMessages 响应补 NotificationMessage 内部结构（`wsnt:Topic@Dialect` ConcreteSet + `tt:SimpleItem` Name/Value）；**O08/O09** §3.6 加"实现期对 Core Spec §5.8.2.2 Table 4 逐字核对 / §8.1.2.4 核实子码组合"注（待核验，不阻塞）。复验轮新增 2 项 MINOR 一并修复：**R1** §9 状态码口径行 200 列改为用例 1–14、16–20（用例 21 归属 500，原统计重复计入）；**R2** §3.1 400 行补消歧（Table 5 Malformed Request 无 body 与 §5.9.1 认证 Fault 带 envelope 两种 400 语义），复验确认 clean。
