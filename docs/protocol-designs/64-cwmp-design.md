# CWMP（CPE 广域网管理协议 / TR-069）设计契约

> 版本：v2.1.1（设计阶段）
> 日期：2026-09-01
> 状态：**尚未实现**；本文定义实现后的 PCAP（抓包文件）断言，不宣称当前测试套件可运行，不修改 Go（编程语言）/MCP（模型上下文协议）实现。**独立隔离对抗审查已完成**（v2.1.1 定稿：独立审查 agent 三向审计 23 项清单（2C/8M/13N）→ 修复 → 复验发现 N01-N03 → 二轮修复 → 二轮复验 clean；审查/修复记录见 §10 修订记录 v2.0.0–v2.1.1）。
> 配套文件：`docs/protocol-designs/64-cwmp-testcase.md`、`trafficgen/test/protocol_pcap/cases/cwmp.json`
> 规范基线：宽带论坛 **TR-069 Issue 1 Amendment 6 Corrigendum 1**（CPE WAN Management Protocol，2020-06，下称 TR-069，按章节号引用）；SOAP 1.1（W3C NOTE-soap-20000508，TR-069 参考文献 [12]）；RFC 7616（HTTP Digest，[9]）、RFC 6265（Cookie，[11]）、RFC 7235（HTTP 认证，[8]）；IANA 服务端口登记（[20]，端口 7547）。

## 1. 范围、profile 和未注册边界

本版定义 CPE（用户驻地设备，Customer Premises Equipment）与 ACS（自动配置服务器，Auto-Configuration Server）之间的 CWMP 明文会话：SOAP 1.1 Envelope（信封）/Header（头）/Body（体）逐字段编码、HTTP/1.1 载体（载体=carrier）规则、Inform/InformResponse 会话建立、参数读写事务（Get/SetParameterValues、GetParameterNames）、GetRPCMethods、Download/Upload/TransferComplete 文件传输、Reboot、SOAP Fault（故障）结构、ACS 主动 Connection Request（连接请求）、空 HTTP 请求/响应会话终止、IPv4/IPv6、多会话与流关联。

| profile（协议档案） | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `cwmp_http_v1` | TCP + HTTP/1.1 明文（ACS URL 端口示例 7547） | SOAP 1.1 over HTTP、TR-069 baseline RPC、Fault、Connection Request、空 POST/空响应 | 设备真实身份、文件真实下载/上传成功、数据模型（TR-181/TR-196）参数语义正确性 |
| `cwmp_ipv6_v1` | TCP + HTTP/1.1 明文 over IPv6 | 同 `cwmp_http_v1`，仅外层地址族不同 | 把 IPv6 四元组自动映射回 IPv4 fixture（固定样本） |
| `cwmp_https_boundary` | TLS/TCP | 仅未来定义：未解密时只观察 TCP/TLS 外层 | 声称看见 HTTP 头、SOAP XML 或 `cwmp:ID` |

显式边界（均为"不实现、不声称、不许静默转换"项）：TR-069 **§3.5 钉死 SOAP 1.1**（envelope 命名空间 `http://schemas.xmlsoap.org/soap/envelope/`），SOAP 1.2 命名空间属线格式错误；HTTPS/TLS 载体本版只声明边界、不设语义用例；Annex K（XMPP 穿透）、Annex G（STUN/UDP 穿透）、STUN/HTTP 代理发现（§3.1 的 DHCP/Option 137 发现链）不在本版；厂商扩展 RPC（`X_<VENDOR>_Method`，A.3.1.1 命名规则）按显式配置透传、不由 profile 自动生成。

当前仓库没有注册 `cwmp` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/cwmp.json` 只保留一个不计入 20 个语义 ID 的注册前置占位 `cwmp_neg_unregistered`（`expect_error=true`、`error_contains="unknown layer"`）。占位的拒绝、0 包或空 PCAP 不得报告为 CWMP 行为通过；注册后按本文 §9 与用例文档 §2 的同一顺序替换为 20 个语义用例。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[tcp, http, cwmp]`（引擎自动补 `ip`；需要显式地址族时写 `[ip, tcp, http, cwmp]` 或 IPv6 等价链）。HTTP 语义（POST/响应头/Content-Length/keep-alive）由 `http` 层承载，`cwmp` 终结层在其上产出 SOAP 1.1 envelope 与事务序列——与 `hls` 同款分层（`[tcp, http, hls]` 先例）。

端口：CWMP 会话由 CPE 作为 HTTP 客户端发起到 ACS URL 的连接，ACS URL 端口按部署配置；IANA 已为 CWMP 登记端口 7547（TR-069 §3.1/§3.2.2 引 [20]），**§3.1 允许 ACS 在其 URL 中使用 7547**，本版 fixture 统一用 `dst_port=7547`。ACS 发起的 Connection Request 反向连到 CPE 的 ConnectionRequestURL，**§3.2.2 允许 CPE 使用 7547**，该方向同样落在 7547。端口可被配置覆盖，但 planner 不得悄然改写。

无 VLAN（虚拟局域网）、IP options（IP 选项）与 TCP options 时，TCP application payload（应用载荷）起点为 IPv4 offset（偏移）54（Ethernet 14 + IPv4 20 + TCP 20）、IPv6 offset 74（14 + IPv6 40 + TCP 20）。HTTP 消息边界由 Content-Length（或合法 chunked）界定，**TCP 分段边界不是 HTTP/SOAP 消息边界**（§3.4.6 还规定 CPE 不得使用 pipelining，即同一连接上请求与响应严格交替）。

## 3. 线格式编码（SOAP/XML 与 HTTP 头，逐项标注出处）

### 3.1 SOAP 1.1 envelope（TR-069 §3.5）

```xml
<soap:Envelope
    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:soap-enc="http://schemas.xmlsoap.org/soap/encoding/"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
  <soap:Header>
    <cwmp:ID soap:mustUnderstand="1">1001</cwmp:ID>
  </soap:Header>
  <soap:Body>
    <cwmp:GetParameterNames>
      <ParameterPath>Device.DeviceInfo.</ParameterPath>
      <NextLevel>0</NextLevel>
    </cwmp:GetParameterNames>
  </soap:Body>
</soap:Envelope>
```

编码规则（均出自 §3.5）：envelope/serialization 命名空间固定为 SOAP 1.1 两个 URI；XML Schema 引用必须用 2001 版命名空间；**CWMP 顶层元素带 `cwmp` 前缀、其内部元素不带前缀**（CWMP schema `elementFormDefault="unqualified"`，§3.5 示例注）；数组参数用 `soap-enc:arrayType` 编码且成员元素名 = 成员类型名（如 `ParameterList` 的成员为 `ParameterValueStruct`）；`anySimpleType` 元素必须带 `xsi:type`；响应方法名 = 请求方法名 + `Response` 后缀。CPE 与 ACS 必须接受总长 ≥32768 字节的 envelope（§3.5 "32 kilobytes" 条款）；响应长度无上界。命名空间版本按 §3.7.4 协商：`urn:dslforum-org:cwmp-1-0`（CWMP 1.0，本版基线）、`cwmp-1-1`、`cwmp-1-2`（1.3/1.4 复用 `cwmp-1-2`，见 A.6 Table 89）。

### 3.2 SOAP Header 元素（§3.5 Table 4）

| Header | 方向 | mustUnderstand | 语义 |
|---|---|---|---|
| `cwmp:ID` | 双向 | 1 | 请求关联标识（任意字符串）；**响应必须回带与请求相同的 ID**（成功或 Fault 均须） |
| `cwmp:HoldRequests` | 仅 ACS→CPE | 1 | 布尔 `0/1`；**已 DEPRECATED** 但 CPE 必须支持 |
| `cwmp:SessionTimeout` | 仅 CPE→ACS 且仅 Inform | 0 | 建议会话超时秒数（≥30） |
| `cwmp:SupportedCWMPVersions` / `cwmp:UseCWMPVersion` | Inform / InformResponse 侧 | 0 / 1 | CWMP 1.3+ 版本协商；本版 fixture 不使用 |

> 本版 fixture **不产生、不解析** `cwmp:HoldRequests`（Table 4 标注已 DEPRECATED，CPE 必须支持但不要求本版 fixture 生成）与 `cwmp:SessionTimeout`（仅 Inform 可带且仅 CPE→ACS，本版 Inform 不带）：二者声明为显式不使用，planner 不得隐式生成或要求解析。

### 3.3 HTTP 层规则（§3.4.1、§3.4.2、§3.4.4–3.4.6）

- 含 SOAP envelope 的 HTTP 请求/响应：`Content-Type: text/xml`（可带 charset）；**含 SOAP 响应或 SOAP Fault 的请求，`SOAPAction` 头必须存在且无值（无引号）**，写作 `SOAPAction:`；空 HTTP POST **不得**带 SOAPAction、**不得**带 Content-Type（§3.4.1）。
- 承载任何 CWMP payload 的 HTTP 响应必须用状态码 200；**空 HTTP 响应必须用 204 No Content**（§3.4.6）。
- 会话 cookie：ACS SHOULD 使用会话 cookie、CPE 必须支持并逐请求回带（§3.4.2 引 RFC 6265）。
- 认证：非 TLS 会话 ACS 必须用 HTTP 摘要认证（§3.4.4），CPE/ACS 必须支持 RFC 7616 `qop="auth"` 与 MD5/MD5-sess（§3.4.5）；CPE 用户名推荐 `<OUI>-<ProductClass>-<SerialNumber>` 格式并按 RFC 3986 百分号编码（§3.4.4）。文件传输服务器可用 basic 或 digest（§3.4.3）。
- HTTP 重定向：CPE 必须支持 302/307，最多连续 5 次，重定向 URL 不得持久化（§3.4.2）。**本版 fixture 不产生 302/307 重定向**：重定向响应由 ACS 侧部署触发，生成器无重定向响应源，声明不适用（见 §8）。

### 3.4 SOAP Fault 结构（§3.5）

Fault 只能作为对 SOAP 请求的响应出现，不得响应另一个响应或 Fault。结构：`faultcode` 取 `Client`（请求方原因）或 `Server`（响应方原因）；`faultstring` 固定文本 **`CWMP fault`**；`detail` 内含 `cwmp:Fault{FaultCode, FaultString, SetParameterValuesFault*}`；`SetParameterValuesFault` 仅用于 SetParameterValues 错误响应，逐参数给出 `ParameterName/FaultCode/FaultString`（§3.5 示例：主 FaultCode 9003 + 逐参数 9007）。

### 3.5 核心方法与参数（Annex A，均标注出处）

| 方法 | 关键参数（类型上限） | 响应 | 出处 |
|---|---|---|---|
| `Inform` | `DeviceId`(DeviceIdStruct：Manufacturer string(64)/OUI string(6) 六位大写十六进制/ProductClass string(64)/SerialNumber string(64))、`Event`(EventStruct[64]：EventCode string(64)+CommandKey string(32))、`MaxEnvelopes`=1、`CurrentTime`(dateTime 带本地时区偏移)、`RetryCount`(uint)、`ParameterList`(ParameterValueStruct[]：Name string(256)+Value anySimpleType) | `InformResponse{MaxEnvelopes=1}` | A.3.3.1 Table 37–39 |
| `GetParameterValues` | `ParameterNames`(string(256)[]，部分路径名以 `.` 结尾) | `ParameterList`(ParameterValueStruct[]) | A.3.2.2 Table 18–19 |
| `SetParameterValues` | `ParameterList`、`ParameterKey`(string(32)) | `Status`(0=已生效，1=待重启生效) | A.3.2.1 Table 15–17 |
| `GetParameterNames` | `ParameterPath`(string(256))、`NextLevel`(boolean) | `ParameterList`(ParameterInfoStruct：Name+Writable boolean) | A.3.2.3 Table 20–22 |
| `GetRPCMethods` | 无参数 | `MethodList`(string[]) | A.3.1.1 Table 13–14 |
| `Download` | `CommandKey`(string(32))、`FileType`(string(64)，枚举 `"1 Firmware Upgrade Image"`/`"2 Web Content"`/`"3 Vendor Configuration File"`/`"4 Tone File"`/`"5 Ringer File"`/`"6 Stored Firmware Image"`/`"X <VENDOR> <id>"`)、`URL`(string(256)，禁止 userinfo 组件)、`Username/Password`(string(256))、`FileSize`(uint，0=未知)、`TargetFileName`(string(256))、`DelaySeconds`(uint，非 0 时禁止同会话执行) | `DownloadResponse{Status 0=已完成并生效，1=未完成, StartTime, CompleteTime}` | A.3.2.8 Table 33–34 |
| `Upload` | 同 Download 参数形状 | `UploadResponse{Status 0/1}` | A.4.1.5 |
| `TransferComplete` | `CommandKey`、`FaultStruct{FaultCode 0=成功；非 0 ∈ {9001,9002,9010,9011,9012,9014–9020}（Table 43）, FaultString}`、`StartTime`、`CompleteTime` | 无参数 | A.3.3.2 Table 41–43 |
| `Reboot` | `CommandKey`(string(32)) | 无参数；CPE 必须先完成会话再重启 | A.3.2.9 Table 35–36 |

下载完成指示三途径（A.3.2.8）：① DownloadResponse Status=0 直接成功；② 同会话后续 TransferComplete；③ **后续新会话** TransferComplete（Status=1 时必须补发）。**三途径由 `cwmp_download_transfer_complete` 三段 fixture 全覆盖**（用例 §4.6：段 A=途径①、段 B=途径② 同会话、段 C=途径③ 跨会话），不再只有途径③有用例。事件码表（§3.7.1.5 Table 8）值域共 14 项（`0 BOOTSTRAP`、`1 BOOT`、`2 PERIODIC`、`3 SCHEDULED`、`4 VALUE CHANGE`、`5 KICKED`、`6 CONNECTION REQUEST`、`7 TRANSFER COMPLETE`、`8 DIAGNOSTICS COMPLETE`、`10 AUTONOMOUS TRANSFER COMPLETE`、`12 AUTONOMOUS DU STATE CHANGE COMPLETE`、`M Download`/`M Reboot`/`M Upload`/`M ScheduleDownload`，CommandKey 随 M 事件携带，A.3.3.1 Table 37 注）；**本版 fixture 实现子集（9 项）**：`0 BOOTSTRAP`（现网首次连接最常见，`cwmp_inform_event_codes` 首跑即断言）、`1 BOOT`、`2 PERIODIC`、`4 VALUE CHANGE`、`6 CONNECTION REQUEST`、`7 TRANSFER COMPLETE`、`M Download`、`M Reboot`、`M Upload`，与用例覆盖表（设计 §9 / 用例 §2）逐项一致；未实现项 `3 SCHEDULED`、`5 KICKED`、`8 DIAGNOSTICS COMPLETE`、`10 AUTONOMOUS TRANSFER COMPLETE`、`12 AUTONOMOUS DU STATE CHANGE COMPLETE`、`M ScheduleDownload` 不进正例，非法值组合仍进负例 20（cwmp_neg_length 锚 `value`）。`"7 TRANSFER COMPLETE" + "M Download"` 等同因事件必须同 Inform 携带（§3.7.1.5）。

### 3.6 错误码值域（A.5.1 Table 87 / A.5.2 Table 88）

CPE 侧：9000 Method not supported、9001 Request denied、9002 Internal error、9003 Invalid arguments、9004 Resources exceeded、9005 Invalid Parameter name、9006 Invalid Parameter type、9007 Invalid Parameter value、9008 Non-writable Parameter、9009 Notification rejected、9010 File transfer failure、9011 Upload failure、9012 File transfer server authentication failure、9013 Unsupported protocol for file transfer（9014–9020 细分传输失败；9800–9899 厂商自定义）。ACS 侧：8000–8005（Method not supported / Request denied / Internal error / Invalid arguments / Resources exceeded / **Retry request**——收到 8005 必须原样重发请求且不得改变任何内容，§3.7.1.6）、8006，8800–8899 厂商自定义。**本版对 ACS 侧错误覆盖子集**：8005 由 `cwmp_fault_soap` 段 B 正例断言（ACS 对 Inform 回 8005 → CPE 原样重发 Inform（`cwmp:ID` 同值、内容逐字节一致）→ ACS 正常 InformResponse）；8002 仅用于段 A 的"Inform 收非 8005 Fault→会话失败终止"正例；其余 ACS 侧错误码（8000、8001、8003、8004、8006）本版不产生（fixture 无该故障触发路径）；非法 FaultCode 值仍进负例 20（`value` 锚）。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性声明**：本引擎对 CWMP 采用**声明式脚本化回放**——配置是剧本（sessions[]/transactions[] 逐条声明），引擎是回放者，按序产出帧；"事件驱动"一词不用于定性整体行为，仅用于两处反应性成分：①自动应答（收到 ACS 请求帧自动补 CPE 响应帧）；②连接边界（事件序列中源端口/角色切换触发新连接，如 Connection Request 反向连接）。

| 现网场景 | 事务交互 | 驱动顺序 | 对应用例 |
|---|---|---|---|
| ① 周期 Inform（最常见：PeriodicInformInterval 触发，§3.2.1） | TCP→POST Inform(2 PERIODIC)→200 InformResponse→空 POST→204→FIN | CPE 驱动全程（§3.7.1 Table 7） | `cwmp_inform_ipv4` |
| ② 参数读写长会话（§3.7.3 Figure 3 原型） | Inform→空 POST→ACS 在响应里发 GetParameterNames/GetParameterValues→CPE POST 响应→ACS 发 SetParameterValues→CPE POST 响应→空 POST→204 | CPE 驱动 HTTP、ACS 驱动 SOAP 请求（§3.7.2 Table 10）；图 3 读段由 `cwmp_get_parameter_values`（用例 4，GetParameterNames+GetParameterValues）、写段由 `cwmp_set_parameter_values`（用例 5）、同连接多事务交替由 `cwmp_http_keepalive_multi_transaction`（用例 11）分载 | `cwmp_get_parameter_values`（读）、`cwmp_set_parameter_values`（写）、`cwmp_http_keepalive_multi_transaction`（多事务交替） |
| ③ ACS 主动连接请求（§3.2.2） | ACS→CPE HTTP GET(:7547)→401 digest 挑战→GET+Authorization→200 空体→CPE 30 秒内新会话 Inform(6 CONNECTION REQUEST) | 反向连接（连接边界反应性成分）后转 CPE 驱动 | `cwmp_connection_request` |
| ④ 配置/固件升级全流程（§3.4.3+A.3.2.8+A.3.3.2） | 会话 1：Inform→ACS 发 Download→DownloadResponse(1)→**204（不关连接）**→**副连接插入**（CPE→文件服务器 HTTP GET，流关联；位置：DownloadResponse 之后、主会话空 POST 之前，主会话挥手最后，见 §5 流关联）→空 POST→204；会话 2：Inform(7 TRANSFER COMPLETE+M Download)→TransferComplete(CommandKey+FaultStruct)→TransferCompleteResponse→空 POST→204 | 主会话驱动副连接（主从关系），跨会话靠 CommandKey 关联；下载完成三途径全覆盖于用例 6 | `cwmp_download_transfer_complete`（三途径）、`cwmp_download_flow_correlation`（副连接时序） |
| ⑤ 日志/配置上报（A.4.1.5） | 会话 1：Inform→ACS 发 Upload→UploadResponse(1)→空 POST→204；会话 2：Inform→TransferComplete→TransferCompleteResponse→空 POST→204 | 同 ④ | `cwmp_upload_transfer_complete` |
| ⑥ 远程重启（A.3.2.9+§3.7.1.5） | 会话 1：Inform→ACS 发 Reboot(CommandKey)→RebootResponse→空 POST→204（终止会话后才重启）；会话 2：Inform(1 BOOT+M Reboot，CommandKey 同值)→空 POST→204 | 跨会话 CommandKey 关联 | `cwmp_reboot_command_key` |

**五层覆盖逐层结论**：功能层——baseline RPC 正例覆盖 Inform/InformResponse、GetParameterValues、GetParameterNames、SetParameterValues、GetRPCMethods、Download（三完成途径）/Upload/TransferComplete、Reboot、Fault（含 8005 重发与 Inform Fault 终止）与空请求/响应终止；每类错误（配置/线格式/状态机/关联/长度）至少一条负例（§7）。性能层——大 SOAP 体跨 MSS 分段重组（`cwmp_mss_large_soap`：envelope ≥32768 字节、默认 MSS 1460、约 23 段，`http.content_length` 断言）+ 32KB envelope 下限 + 参数长度上界断言。数据场景层——事件码枚举（9 项实现子集）、FileType 枚举（代表值 1/3 + 其余入负例非法值）、Status 0/1、FaultCode 值域、faultcode Client/Server 二值、ParameterKey 空/非空（含 32 字符上界）、FileSize=0、DelaySeconds=0/非 0（非 0 时同会话不得执行副连接/TransferComplete，段 C 断言）、Event 数组满 64、MaxEnvelopes=1、string(256/64/32) 上界、XML 转义（`&amp;`）、OUI 六位大写十六进制、dateTime 带时区偏移、用户名百分号编码（§8 逐项断言归属）。地址与流层——IPv4/IPv6 独立 fixture、单流基线、Download 副连接**流关联**、多会话双四元组；**多流（一个会话内部并发流）显式不适用**：§3.4.6 禁止 pipelining，一个 CWMP 会话内只有严格交替的单 HTTP 事务流。业务层——周期上报、ACS 主动排查、批量参数管理、升级、上报、重启均为现网日常，优先于教科书全方法遍历。

**次要合法行为显式不适用声明（均不设正例用例，亦不得进负例，§7 防误报同步）**：① HTTP 重定向 302/307（§3.4.2）——重定向响应由 ACS 侧部署触发，本版生成器无重定向响应源，声明不适用；② HTTP chunked 传输编码（§2 允许 chunked 界定边界）——本版所有 HTTP 实体一律用 Content-Length 界定（边界可预算、断言可执行），chunked 不进 fixture；③ CPE 已在会话时对 Connection Request 回 503（§3.2.2）——本版 CR fixture 均取 CPE 空闲态（401→200 成功路径），不模拟"会话占用"窗口，声明不适用；④ 失败会话重试（§3.2.1.1）——本版 Inform 会话均为成功会话（RetryCount=0），不产生失败→重试序列；⑤ 文件服务器 basic/digest 认证（§3.4.3）——本版副连接文件服务器为公开 URL（无 401 挑战，见 `cwmp_download_flow_correlation`），basic/digest 认证分支不进 fixture；⑥ `X_<VENDOR>_Method` 厂商扩展 RPC（§1/A.3.1.1）——透传能力已声明于 §1，本版无厂商扩展 fixture。

## 5. 消息/事务模型与状态机

**事务定义**：CWMP 事务 = 同一 HTTP 会话内一次完整的请求/响应交互，关联标识为 SOAP Header `cwmp:ID`（响应必须回带同值，§3.5 Table 4）。**多事务** = 一个 TCP 连接内多笔事务按序执行且事务间有依赖：Inform 必须是会话第一笔事务（A.3.3.1 "MUST call Inform … whenever a Session is established"）；后续事务靠 ID 递增匹配；TransferComplete 的 CommandKey 必须回指同会话或前会话 Download/Upload 的 CommandKey。**事务交互**示例：先 GetParameterValues 读、后 SetParameterValues 写（Figure 3 顺序）；先 Download 下发、后 TransferComplete 上报（跨会话）。

CPE 侧会话状态机（§3.7.1）：

| 状态 | 允许事件 | 必须保持 |
|---|---|---|
| `TransportReady` | TCP 建立后首个 HTTP POST | 首笔 SOAP 事务必须是 Inform（含 HTTP 认证挑战时先补 Authorization） |
| `InformPending` | 200 InformResponse | `cwmp:ID` 与 Inform 相同；MaxEnvelopes=1 |
| `CpeRequests` | CPE 有待发请求时 POST 请求；否则空 POST（Table 7） | 空 POST 无 SOAPAction/Content-Type；发出后本会话不得再发请求（§3.7.1.3） |
| `AcsRequests` | ACS 请求随 HTTP 响应到达→CPE 下一 POST 必须是其 Response | 不得响应另一个响应、不得响应 Fault（§3.5）；违规进负例 18（锚 `session`/`state`） |
| `Faulted` | 非 Inform 事务收到 Fault | **会话继续**（§3.7.1.4，正例 `cwmp_fault_soap` 段 B 断言）；Inform 收到 8005→原样重发 Inform（`cwmp_fault_soap` 段 B 第 1-2 对事务）；Inform 收到非 8005 Fault→**会话失败终止**（正例 `cwmp_fault_soap` 段 A 断言：无空 POST、无后续事务，直接挥手） |
| `Terminating` | 空 POST 后等空响应（204） | 双方 Table 7/Table 10 条件全满足后才关连接 |
| `Closed` | TCP FIN | 关闭后不得产生新业务帧；失败会话按 §3.2.1.1 重试 |

ACS 侧对称（§3.7.2 Table 10）：CPE 请求未决时响应；CPE 无请求且 ACS 有请求时在响应里发请求；均无则空 HTTP 响应（204）。**会话收尾教义：每个正常会话以空 POST/204 对收尾**——204 只有在应答空 POST 时才终止会话；应答 DownloadResponse、SetParameterValuesResponse 等**非空 POST** 的 204 表示 ACS 无后续请求，会话继续（用例 11 中段 204 为佐证），直至收尾的空 POST/204 对。

**流关联**（控制流派生数据流的主从关系）：① Download/Upload 的文件传输副连接——§3.4.3 允许同连接、第二连接、终止会话后传输三种方式；URL 与 ACS 不同域/端口时只能后两种，本版 fixture 取"第二连接"：CPE 以新源端口向文件服务器发起独立 HTTP GET/PUT，主会话保持。副连接由主会话 Download 事务的 URL/CommandKey 驱动，配置以 `driven_by` 显式声明主从（§6）。**副连接在多会话展开中的插入位置（唯一确定）**：紧跟主会话 DownloadResponse 事务之后、主会话空 POST 之前发起并完成（副连接自身：握手→GET/200→挥手），完成后主会话才继续空 POST→204→挥手——主会话挥手是整个主会话块的最后一帧组；主会话对 DownloadResponse 的应答帧同为 204（不关连接：应答非空 POST 的 204 不终止会话，见 ACS 侧收尾教义），会话以收尾的空 POST/204 对终止。多会话包号 = 各块顺次之和（主会话块内嵌副连接块，下一会话握手包号 = 前一会话块总包数 + 1）。② Connection Request 反向连接——ACS 作为 HTTP 客户端连 CPE（连接边界反应性成分），认证成功后 CPE 在 30 秒内**另起** CPE→ACS 会话（§3.2.2），两个连接四元组与角色均不同。多会话（多个独立连接、状态不串用）与流关联不是同一维度：`cwmp_multi_session` 证明前者，`cwmp_download_flow_correlation` 证明后者。

## 6. 配置 typedef（JSON 形状示例，非 Go 代码）

```json
{
  "layers": [{"tcp": {}}, {"http": {}}, {"cwmp": {}}],
  "src_ip": "192.0.2.65", "dst_ip": "198.51.100.65",
  "src_port": 50065, "dst_port": 7547,
  "cwmp": {
    "profile": "cwmp_http_v1",
    "namespace": "urn:dslforum-org:cwmp-1-0",
    "sessions": [
      {
        "role": "cpe", "src_port": 50065, "dst_port": 7547,
        "transactions": [
          {"kind": "inform", "id": "1001", "events": [{"code": "2 PERIODIC", "command_key": ""}],
           "device_id": {"manufacturer": "Example", "oui": "001122", "product_class": "GW", "serial": "SN0001001"},
           "parameter_list": [{"name": "Device.DeviceInfo.SoftwareVersion", "value": "1.0.0"}]},
          {"kind": "inform_response", "id": "1001", "max_envelopes": 1},
          {"kind": "acs_request", "method": "get_parameter_values", "id": "1002",
           "parameter_names": ["Device.DeviceInfo.", "Device.ManagementServer.URL"]},
          {"kind": "acs_response", "for_id": "1002",
           "parameter_list": [{"name": "Device.DeviceInfo.Manufacturer", "value": "Example"}]},
          {"kind": "empty_post"},
          {"kind": "empty_response", "status": 204}
        ]
      },
      {
        "role": "acs_cr", "src_port": 51000, "dst_ip": "192.0.2.65", "dst_port": 7547,
        "transactions": [
          {"kind": "connection_request"},
          {"kind": "auth_challenge", "status": 401, "digest": "Digest realm=\"cpe\", nonce=\"abc\", qop=auth"},
          {"kind": "connection_request", "authorized": true},
          {"kind": "empty_ok", "status": 200}
        ]
      }
    ],
    "flows": [
      {"kind": "http_get", "src_port": 50066, "host": "203.0.113.10", "port": 80,
       "uri": "/fw/1.2.3.bin", "file_b64": "",
       "driven_by": {"session": 0, "transaction": "download", "field": "url"}}
    ],
    "wire_fault": ""
  }
}
```

形状要点：`sessions[]` = 统一术语的**事件编排会话**（每个自带四元组与事务序列，多会话展开按序整块回放，第二会话包号起点 = 前会话总包数 + 1）；`transactions[]` 即会话的**事件序列**，元素为一笔**事务**（kind 覆盖 inform/inform_response/acs_request/acs_response/cpe_response/download/download_response/upload/upload_response/transfer_complete/transfer_complete_response/reboot/reboot_response/get_rpc_methods(_response)/fault/connection_request 三步/empty_post/empty_response）；`flows[]` = 流关联副连接声明，`driven_by` 把副连接锚到主会话事务的字段（URL/CommandKey），校验器必须检查主从引用成立；`wire_fault` 仅负例注入口（取值 `soap`/`http`/`session`/`correlation`/`length`/`carrier`），不得成为线上字段。并发会话（`concurrent: true`）本版不适用——CWMP 会话本身单连接串行，双会话用多会话展开表达。

## 7. 错误处理（负例锚词表）

以下输入必须由 planner/validator 拒绝并传播为 task error（任务错误），不得产出成功 PCAP、`completed/0 packet` 或仅 TCP/HTTP 外壳的假成功。锚词（anchor word）为 `error_contains` 断言字面值，与用例文档 §5 一一对应：

| 负例 ID | 故障输入（方向） | `error_contains` 候选锚词 |
|---|---|---|
| `cwmp_neg_config` | 配置错：profile/namespace 版本不匹配（如 SOAP 1.2 命名空间）、层链缺 http（tcp→cwmp 直连）、端口/载体声明矛盾 | `profile`、`namespace`、`carrier` 或 `port` |
| `cwmp_neg_http_wire` | HTTP 线格式错：方法非 POST、SOAPAction 非空值、Content-Type 非 text/xml、Content-Length 与实体不符、401 挑战后 Authorization 缺失或摘要错仍继续 | `http`、`method`、`auth` 或 `content-type` |
| `cwmp_neg_xml_soap` | SOAP/XML 线格式错：XML 截断/不合法、envelope 命名空间错、Body 缺失、响应缺 `Response` 后缀、Fault 结构不符（faultstring≠`CWMP fault`、detail 缺 cwmp:Fault） | `xml`、`soap`、`envelope` 或 `fault` |
| `cwmp_neg_session_state` | 状态机错：非 Inform 首事务、空 POST 后继续发请求、CPE 发送 ACS 方法（方向错）、Fault 后继续同事务、Fault 响应 Fault、响应另一个响应、会话未终止即重启 | `session`、`state` 或 `sequence` |
| `cwmp_neg_correlation` | 关联错：响应 `cwmp:ID` 与请求不匹配、TransferComplete CommandKey 无来源 Download/Upload、`driven_by` 副连接引用不存在的事务/字段 | `id`、`command` 或 `correlation` |
| `cwmp_neg_length` | 长度/值域错：参数名 >256、CommandKey >32、事件码/FaultCode/FileType 非法值、Event 数组 >64、超长实体截断 | `length`、`parameter` 或 `value` |

**不得误报为 planner error 的合法协议事件**：SOAP Fault 响应本身（正例 `cwmp_fault_soap`）、DownloadResponse Status=1（升级未完成属正常路径）、Connection Request 的 401 挑战与 200/204 空体、CPE 已在会话时对 CR 回 503（§3.2.2）、8005 Retry request 后原样重发（§3.7.1.6）、空 ParameterList（A.3.2.2：无匹配参数时空表不报错）、FileSize=0（=大小未知）。只有配置、线格式、长度或关联错误进入负例。

## 8. 边界

大 SOAP 体：MSS 分段后必须按 Content-Length/重组流还原 envelope 再断言（`cwmp_mss_large_soap` 用 ≥32768 字节 SOAP envelope——其 ParameterList ≥32768 字节，**默认 MSS 1460、不压 MSS**，段数 = ceil(envelope 总长/1460) ≈ 23 段；断言 `http.content_length` = envelope 实际字节长且 ≥32768，覆盖 §3.5 的 32KB envelope 下限）；生成器不得按未限定长度分配。地址族：IPv4/IPv6 用独立 fixture，同一逻辑 envelope 的 SOAP 字节必须一致，仅外层 IP 头与偏移（54/74）不同（v6 fixture 取 src `2001:db8::65`、dst `2001:db8::1`、dst_port 7547）。多会话：≥2 个独立四元组，`cwmp:ID` 计数、cookie、DeviceId、事务状态互不串用；会话间包序按多会话展开，副连接按 §5 流关联插入。参数/值域边界**逐项断言归属**（正例均落实，不再是无用例声明）：空 ParameterList（`cwmp_inform_event_codes` fixture 3，无 `ParameterValueStruct` hex）、空 ParameterKey（`cwmp_set_parameter_values` 第 1 笔 SetParameterValues，合法且保持为空）、Event 数组满 64（`cwmp_inform_event_codes` fixture 4）、FileSize=0（`cwmp_download_transfer_complete` 段 A，0=大小未知）、DelaySeconds=0（段 B，同会话可执行）/非 0（段 C，同会话不得执行副连接与 TransferComplete）、string(256) 参数名上界（`cwmp_get_parameter_values`）、string(64) DeviceId 字段上界（`cwmp_inform_event_codes` fixture 1）、string(32) CommandKey/ParameterKey 上界（`cwmp_set_parameter_values`/`cwmp_download_transfer_complete`）、OUI 六位大写十六进制（`cwmp_inform_event_codes` fixture 1，`^[0-9A-F]{6}$`）、dateTime 必带时区偏移（`cwmp_inform_event_codes` fixture 1，CurrentTime 含 `+hh:mm`/`-hh:mm`）、XML 转义（`&amp;` 等，`cwmp_inform_event_codes` fixture 1 的参数值）、用户名百分号编码（§3.4.4，`cwmp_connection_request` 的 `http.authorization` 含 `%20` 编码值）。HTTP 重定向 302/307、chunked、CR 忙 503、失败会话重试、文件服务器 basic/digest、`X_` 厂商 RPC 见 §4 不适用声明。不得产生回绕长度或超量分配。

## 9. 原子 ID 与完成定义

设计、testcase 与未来 `cwmp.json` 必须使用同一组 20 个唯一语义 ID（14 正 + 6 负）、同一顺序；当前 JSON 另有不计入的 `cwmp_neg_unregistered` 占位。

| # | ID | 类型 | 覆盖 |
|---:|---|---|---|
| 1 | `cwmp_inform_ipv4` | 正 | IPv4/7547 单流基线：Inform(2 PERIODIC)→InformResponse→空 POST→204 |
| 2 | `cwmp_inform_event_codes` | 正 | 事件码实现子集 9 项中本用例断言 5 项（0 BOOTSTRAP+1 BOOT、4 VALUE CHANGE、7 TRANSFER COMPLETE+M Download）；其余 4 项：2 PERIODIC 见用例 1、1 BOOT+M Reboot 见用例 9、6 CONNECTION REQUEST 见用例 3、M Upload 见用例 8。另断言 Event 数组满 64、DeviceId string(64/6) 上界、OUI 大写十六进制、dateTime 时区偏移、XML 转义、空 ParameterList |
| 3 | `cwmp_connection_request` | 正 | ACS→CPE GET/401 digest（`qop="auth"`）/200 空体 + 新会话 Inform(6 CONNECTION REQUEST)；用户名百分号编码 |
| 4 | `cwmp_get_parameter_values` | 正 | GetParameterValues 与 GetParameterNames 事务（数组编码、部分路径、Writable、string(256) 参数名上界） |
| 5 | `cwmp_set_parameter_values` | 正 | 两笔 SetParameterValues 事务：Status 0/1 各一次；ParameterKey 空（合法保持空）与 32 字符上界各一次 |
| 6 | `cwmp_download_transfer_complete` | 正 | 下载完成三途径全覆盖（A.3.2.8）：段 A=①DownloadResponse Status=0 直接成功、段 B=②同会话 TransferComplete、段 C=③新会话 TransferComplete（CommandKey 跨会话关联）；FileSize=0、DelaySeconds=0/非 0、CommandKey 32 上界、FileType 代表值 1/3 |
| 7 | `cwmp_download_flow_correlation` | 正 | 流关联：Download 驱动独立副连接 HTTP GET 文件服务器；副连接插在 DownloadResponse 之后、主会话空 POST 之前、主会话挥手最后（§5） |
| 8 | `cwmp_upload_transfer_complete` | 正 | Upload→UploadResponse(1)→新会话 Inform(7 TRANSFER COMPLETE+M Upload)→TransferComplete |
| 9 | `cwmp_reboot_command_key` | 正 | Reboot→RebootResponse→新会话 Inform(1 BOOT+M Reboot，CommandKey 同值) |
| 10 | `cwmp_fault_soap` | 正 | 段 A：Inform 收非 8005 Fault→会话失败终止（faultcode Server、FaultCode 8002）；段 B：Inform 收 8005→原样重发（ID 同值）→SetParameterValues 触发 Fault（faultcode Client、主码 9003+SetParameterValuesFault 逐参数 9007、faultstring=CWMP fault）→非 Inform Fault 后会话继续 |
| 11 | `cwmp_http_keepalive_multi_transaction` | 正 | 同连接多事务（Inform→GetRPCMethods→SetParameterValues→空 POST→204），无 pipelining |
| 12 | `cwmp_ipv6` | 正 | IPv6 单流 Inform 会话（src `2001:db8::65`、dst `2001:db8::1`、dst_port=7547；ipv6.nxt=6、offset 74） |
| 13 | `cwmp_multi_session` | 正 | 多会话展开双四元组，ID/cookie/状态不串用 |
| 14 | `cwmp_mss_large_soap` | 正 | 大 SOAP 体跨 MSS 分段重组：envelope ≥32768 字节、默认 MSS 1460、≈23 段，`http.content_length` 断言 32KB 下限 |
| 15 | `cwmp_neg_config` | 负 | 配置错（profile/namespace/层链/端口） |
| 16 | `cwmp_neg_http_wire` | 负 | HTTP 线格式错（method/SOAPAction/Content-Type/长度/auth） |
| 17 | `cwmp_neg_xml_soap` | 负 | SOAP/XML 线格式错（namespace/envelope/Fault 结构） |
| 18 | `cwmp_neg_session_state` | 负 | 状态机错（首事务、空 POST 后续发、方向、Fault 后续） |
| 19 | `cwmp_neg_correlation` | 负 | 关联错（ID 错配、CommandKey 无来源、副连接主从不符） |
| 20 | `cwmp_neg_length` | 负 | 长度/值域错（上界越界、非法枚举、截断） |

完成定义：注册 `tcp→http→cwmp` 层链；逐字段生成 §3 的 SOAP envelope/Header/Fault 与 HTTP 头；Inform/RPC/Fault（含 8005 重发与 Inform Fault 终止）/空请求响应、Connection Request、Download 三完成途径与副连接流关联（插入位置可观测）、多会话展开、IPv4/IPv6、MSS 分段（≥32768 字节 envelope、默认 MSS 1460）与 §8 逐项边界断言均可观测；20 个语义 ID 正负断言与错误传播完成；未注册阶段只接受 `unknown layer` 占位。

## 10. 修订记录

- v1.0.0（2026-08-20）：旧稿首版（14 正 + 6 负：含 https_tls_opaque、pcap_nic_consistency、multi_flow_dynamic_fields 等 ID）。
- v2.0.0（2026-08-31）：按《协议设计文档与用例文档需求文档 v1》三向对抗审查流程重写，取代 2026-08-20 旧契约稿（旧稿见 git 历史）。对照 TR-069 Issue 1 Amendment 6 Corrigendum 1 全文逐节校准（新增章节级出处：§3.4.1 SOAPAction/Content-Type 规则、§3.4.6 空 204/禁 pipelining、§3.5 Table 4 Header 与 Fault 结构、§3.7.1.5 Table 8 事件码、A.3.3.1 Table 37–39 Inform、A.3.2.8 Download 三完成途径、A.5.1/A.5.2 错误码表）；按统一术语重排 20 个语义 ID——删除 `pcap_nic_consistency`（测试方法非协议语义）、`multi_flow_dynamic_fields`（CWMP 禁 pipelining，多流不适用）、`https_tls_opaque`（降为 §1 未注册边界声明），新增流关联（`cwmp_download_flow_correlation`）、多事务（`cwmp_http_keepalive_multi_transaction`）、多会话展开（`cwmp_multi_session`）、性能（`cwmp_mss_large_soap`）与独立 v4/v6 用例；新增 §4 业务场景分析（五层逐层）、§5 状态机与事务模型、§6 JSON 配置 typedef。三向对抗审查 2 轮：第 1 轮修正 InformResponse 独立成例造成的覆盖重叠（并入 inform_ipv4/事件码用例）、补 MSS 性能用例缺口、Connection Request 401 从"负例"归位为正例路径；第 2 轮规范回对抽查 FaultCode 表/事件码组合/32KB 下限/7547 端口语义，结论 clean。
- v2.1.0（2026-09-01）：依据《协议设计文档与用例文档需求文档 v1.1》（§3 独立子代理隔离对抗审查；64-cwmp 按 v1.0 完成后补本轮隔离审查），独立子代理隔离对抗审查 23 项问题清单（2 CRITICAL / 8 MAJOR / 13 MINOR）修复轮，全部 CRITICAL/MAJOR 关闭、MINOR 项关闭或显式声明。关键修复：**X01**（CRITICAL）`cwmp_fault_soap` 的 SetParameterValuesFault 改由 ACS 触发 SetParameterValues 的独立事务承载（原错误挂在 GetParameterValues Fault 帧），段 B 重排为 4 对事务 = 15 包；**X02**（CRITICAL）删除"MSS 压 536"自相矛盾配置，`cwmp_mss_large_soap` 改用默认 MSS 1460；**X03** 副连接插入位置唯一确定（DownloadResponse 之后、主会话空 POST 之前、主会话挥手最后），§5/§8 与用例公式同步；**X04** envelope 拉到 ≥32768 字节（覆盖 32KB 下限）并断言 `http.content_length`；**X05** 下载完成三途径全部入 `cwmp_download_transfer_complete`（段 A/B/C）；**X06** 补 8005 原样重发正例（段 B 前两对）与 Inform 非 8005 Fault 会话失败终止正例（段 A）；**X07** HoldRequests/SessionTimeout 显式声明 fixture 不使用；**X08** 事件码 14 项取值域声明本版实现子集 9 项并补 `0 BOOTSTRAP` 正例；**X09/X10** 零/空/满与编码边界逐项落到具体用例断言（§8 断言归属表）；**X15/X19** 负例故障输入统一为两文档并集（补"Fault 响应 Fault""响应另一个响应""摘要错"）；**X16** 场景②对齐用例 4/5/11 分载；**X18/X20** 次要合法行为（302/307、chunked、CR 忙 503、失败会话重试、文件服务器认证、X_ 厂商 RPC）逐项显式不适用声明；**X21** 契约引用改 v1.1；**X22** digest 断言升级含 `qop="auth"`；**X11** FileType 补代表值 1/3；**X12** faultcode Client/Server 二值断言；**X13** `cwmp_set_parameter_values` 改 15 包（4 对）；**X14** `cwmp_inform_event_codes` 改四次 fixture 与列举一致；**X17** IPv6 目的地址明确 `2001:db8::1`、`dst_port=7547`（消除地址与端口混写笔误）。**X23**（MINOR，原子性拆分）case 4 已拆为两会话块（GetParameterNames/GetParameterValues 各一独立会话，26 包）；case 10 拆为两段（段 A Inform Fault 终止、段 B 8005 重发+SetParameterValuesFault）、case 6 三段、case 2 四次 fixture，均按段独立 packet_count 与断言。case 13 多维度合一拆不动：多会话展开是单一规格点（§5），ID/cookie/DeviceId/状态不串用是同一行为的多个可观测断言面，逐维度单独设例需以 2 会话重复铺陈且要新增 ID——20 个语义 ID 与 §9/用例 §2/JSON 三方顺序契约为脚本核验的固定结构，拆分即破坏契约；按需求 §7"复合用例既是原子用例的顺次组合"处理并在此注明。
- v2.1.1（2026-09-01）：复验不通过修复轮（N01/N02/N03）。**N01**（CRITICAL）删除全部"200 空体（非 204）"提法（§5 流关联末句、§4 场景④），DownloadResponse 等非空 POST 的应答统一为 204——空 HTTP 响应必须 204（§3.4.6，本文 §3.3 已钉死）；依据 §5 Terminating 钉死教义：204 只有在应答空 POST 时才终止会话，应答非空 POST 的 204 会话继续（用例 11 中段 204 佐证）。**N02**（MAJOR）统一会话收尾为"空 POST/204 对收尾"（§5 新增教义句），A 式（最后非空 POST 被 204 应答后直接挥手）全部改 B 式并全表重算 packet_count：用例 2 → 44（4×11）、用例 4 → 30（两会话各 +2）、用例 5 → 17、用例 6 → 69（段 A 15、段 B 26、段 C 28）、用例 8 → 28、用例 9 → 26、用例 10 → 28（段 B 19，"不许两式混用"同样适用）、用例 13 → 30（第二会话握手包号改 16）、用例 7/11 包数不变（仅 DownloadResponse 应答与中段 204 措辞改 204）。Connection Request 的 200 空体保留（§3.2.2 CR 成功应答即 200 无体，非会话空响应范畴）。**N03**（MINOR）v2.0.0 修订条目的需求文档引用改回 v1（该轮实际按 v1.0 完成提交），v1.1 引用仅保留于 v2.1.0 及本条目。
