# MMSE（多媒体消息服务封装，Multimedia Messaging Service Encapsulation）设计契约

> 版本：v2.0.1（设计阶段）
> 日期：2026-09-01
> 状态：**独立隔离对抗审查已完成**（v2.0.1 定稿：独立审查 agent 三向审计 10 项清单（2M/8N）→ 修复 → 复验 9.5/10 → 复验新发现 R1 修复 → 抽查确认 clean；审查/修复记录见 §10 修订记录 v2.0.0/v2.0.1）。
> 配套文件：`docs/protocol-designs/71-mmse-testcase.md`、`trafficgen/test/protocol_pcap/cases/mmse.json`（当前 JSON 仅含注册前置占位，本版不写文件、不改代码）
> 规范基线：WAP 论坛 **WAP-209-MMSEncapsulation-20020105-a**（Multimedia Messaging Service Encapsulation，2002-01-05，MMS 1.0 基线，下称 WAP-209，按章节号引用，全文已取回核对）；**OMA-MMS-ENC v1.1/v1.2/v1.3**（OMA 继任版，MMS 1.1+ 扩展 PDU 与字段：m-read-rec-ind、X-Mms-Retrieve-Status、X-Mms-Read-Status 等）；WAP-206-MMSCTR-20020115-a（MMS Client Transactions，事务流图 Figure 3/4/5 出处）；WAP-230-WSP-20010705-a（无线会话协议——**编码原语与 multipart 结构的规则来源**，其承载本身是本版边界，见 §1）；RFC 2387（multipart/related）、RFC 822（消息头与地址）、RFC 2616/7230（HTTP/1.1）、RFC 2045/2046（MIME）。
> 修订记录：v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》重写，取代 2026-08-21 旧稿（旧稿见 git 历史）。**规范编号更正**：任务口径"WAP-230-MMS-ENC 1.3（2003-01）"经档案索引核实不存在——WAP-230 是 WSP 规范编号，MMS 封装规范为 WAP-209（1.0，2002-01）及 OMA-MMS-ENC（1.1–1.3）继任版；本文按实际文档引用。

## 1. 范围、profile 和未注册边界

本版定义 MM1 接口（MMS 终端 ↔ MMS 代理中继，WAP-209 §3.2 "MMS Client / MMS Proxy-Relay"）的 MMS PDU 二进制封装：8 类 PDU（m-send-req / m-send-conf / m-notification-ind / m-notifyresp-ind / m-retrieve-conf / m-acknowledge-ind / m-delivery-ind / m-read-rec-ind）逐字段编码、值域与状态码、multipart 消息体（multipart/related + SMIL 演示部件 + 文本/图片附件）、事务关联规则、IPv4/IPv6、多会话与多事务。

| profile（协议档案） | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `mmse_http_v1`（主 profile） | TCP + HTTP/1.1 明文（默认端口 80，MMSC URL 可配置覆盖） | 8 类 PDU 的 HTTP POST / GET / 响应体回放、multipart/SMIL/附件、全部头部字段与值域、多事务 keep-alive | 真实运营商 MMSC 语义（鉴权、彩信中心路由、计费）、真实终端渲染/播放 |
| `mmse_http_v6` | 同上，IPv6 | 同 `mmse_http_v1`，仅外层地址族不同 | 把 IPv6 四元组映射回 IPv4 fixture |
| `mmse_wsp_boundary` | WAP WSP/WTP（UDP 9200/9201）或 WAP Push（SMS 承载） | 仅边界声明，不实现、不声称 | WSP 会话管理/能力协商、WTP 事务、push 端口语义 |

**载体决策与理由**：现网 MMSE（Android/iOS 彩信 APN 上的 MM1 接口）以 **HTTP POST + `Content-Type: application/vnd.wap.mms-message`** 传输，故本版主 profile 走 `http` 层（与 `cwmp`/`doh`/`onvif` 同款分层：`[tcp, http, mmse]`）。WAP-209 §7 原文："The encoded MMS messages are stored to the Data field of the Post, Reply and Push PDUs [WAPWSP]"——**PDU 字节与承载无关**，同一 PDU 字节装入 WSP Post/Reply/Push 或 HTTP 请求/响应体；HTTP 承载属规范允许形态。WSP/WTP 与 WAP Push（SMS）承载为本版**未注册边界**：不实现、不声称、不许静默转换。

**通知/递送报告的 HTTP 回放语义（显式声明）**：M-Notification.ind 与 M-Delivery.ind 都是 MMSM/MM1 接口上的 PDU（WAP-206 §6 Figure 3/5 事务流），但它们是**网络侧发给 MS 的单向指示**——在 WAP profile 下经 WAP Push（SMS/UDP 2948 WSP Push PDU）投递到终端（WAP-209 §7 "The encoded MMS messages are stored to the Data field of the Post, Reply and **Push** PDUs"），该承载是本版边界。本版以**HTTP 承载回放这两个 PDU 的编码、字段与关联语义**：生成器同时扮演 MS 与 MMSC 两端，将通知/递送报告作为 MMSC→MS 方向连接上的 HTTP POST 体回放（PDU 字节与规范定义完全一致，仅承载路径非现网复刻）；M-NotifyResp.ind / M-Acknowledge.ind / M-Read-Rec.ind 则按 AOSP 实现先例（NotifyRespTransaction/AcknowledgeTransaction/ReadRecTransaction 均为 HTTP POST）由 MS 侧 POST 上送。

**未注册边界**：当前仓库没有注册 `mmse` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/mmse.json` 只保留一个不计入语义 ID 的注册前置占位 `mmse_neg_unregistered`（`expect_error=true`、`error_contains` 精确为 `unknown layer`）。占位的拒绝、0 包或空 PCAP 不得报告为 MMSE 行为通过；注册后按本文 §9 与用例文档 §2 的同一顺序替换为语义用例。MMS 1.1 扩展 PDU m-read-orig-ind（0x88）/m-forward-req（0x89）/m-forward-conf（0x8A）、MMS 1.2/1.3 扩展 PDU（m-mbox-store/view/upload/delete/delete-conf 系列，线码 0x8B–0x93）与 Reply-Charging 字段族（0x9C–0x9F）本版不实现—— read-orig/forward 无现网部署实例、mailbox 系列现网已废弃、Reply-Charging 未在中国运营商网络部署；PDU 类型值域表（§3.7）中保留其定义但标注"本版不产生"。**归口**：已分配但本版不产生的 PDU 值（0x88–0x93）或 Reply-Charging 字段族出现在配置时，按 §7 `mmse_neg_unknown_pdu_type` / `mmse_neg_value_range` 显式拒绝（不静默转换、不假成功）。

**编码形态产生范围（显式声明）**：本版**产生**——Text-string 裸形态与 Value-length+charset 形态（charset 恒 106=UTF-8）、Text-string **Quote 形态**（首字符为分隔符时前置 0x7F，§3.3；用例 `mmse_text_string_quote`）、From **insert-address-token** 形态（§3.4；用例 `mmse_from_insert_token`）。本版**不产生**——空串 Text-string（仅 0x00 终止）、Application-header 扩展头（§3.4 末行）、charset 非 106 值（含 1000=UCS-2、17 等）：生成器无对应编码路径，配置声明时按 §7 `mmse_neg_value_range` 归口拒绝。§3.7 值域表为协议全集；已实现形态内未进入本版用例的合法枚举值（如 Priority=Low、Status=Rejected/Unrecognised）仍为合法协议值，但不构成本版覆盖声明（§4 实测集合收窄）。

**动态值不硬编码**：Transaction-ID、Message-ID、multipart 附件内容、日期时间戳为运行期或配置值。断言策略：Transaction-ID / Message-ID 用 `same_as_packet`（关联断言）与 `nonzero`；日期用 `nonzero`（绝对时间显示含本地时区，不稳定）；附件内容用 `nonzero` + frames hex（magic bytes 前缀）；其余值域字段（message-type / status / class / priority 等）为预配置枚举值，允许 fixture 显式给出精确值。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[tcp, http, mmse]`（引擎自动补 `ip`；IPv6 写 `[ipv6, tcp, http, mmse]`）。HTTP 语义（请求行/响应行/头/Content-Length/keep-alive）由 `http` 层承载，`mmse` 终结层在其上产出 MMS PDU 字节与事务序列。

端口：MMSC URL 端口按部署配置（现网常见 80 或 8002）；本版 fixture 统一 `dst_port=80`。端口可被配置覆盖，planner 不得静默改写。M-Notification/M-Delivery 回放连接（MMSC→MS 方向）由配置显式给四元组，无隐式端口推导。

固定偏移：无 VLAN、IP options、TCP options 时，HTTP 起行起点为 IPv4 offset（偏移）54（Ethernet 14 + IPv4 20 + TCP 20）、IPv6 offset 74（14 + IPv6 40 + TCP 20）。**MMS PDU 在 HTTP body 内，偏移不固定**——PDU 起点 = 54/74 + 该 fixture 固定 HTTP 头集合的字节长（头集合由配置钉死，偏移可预算：`PDU 起点 = 54/74 + len(请求行/状态行 + 固定头集合 + CRLF 空行)`）。PDU 内部偏移见 §3.2/§3.3（首字段固定在 PDU offset 0）。HTTP 消息边界由 Content-Length 界定，**TCP 分段边界不是 HTTP/MMS 消息边界**（RFC 7230 §3.3.2；跨 MSS 用例见 §8）。

## 3. 线格式编码（逐项标注出处）

### 3.1 HTTP 载体规则（WAP-209 §4 "the WAP WSP/HTTP is used to transfer multimedia messages"；RFC 7230）

| 交互 | HTTP 形态 | body |
|---|---|---|
| 提交 | UA→MMSC `POST /mms HTTP/1.1` + `Content-Type: application/vnd.wap.mms-message` | m-send-req PDU |
| 提交确认 | 同连接 `HTTP/1.1 200 OK` + 同 Content-Type | m-send-conf PDU |
| 通知（回放） | MMSC→MS 方向连接 `POST` + 同 Content-Type | m-notification-ind PDU |
| 通知确认 | MS→MMSC `POST` | m-notifyresp-ind PDU |
| 取回 | MS→MMSC `GET <Content-Location URI>` | 无 body（WAP-209 §6.3 "WSP/HTTP GET request … containing a URI"；URI 即通知的 Content-Location） |
| 取回响应 | `HTTP/1.1 200 OK` + 同 Content-Type | m-retrieve-conf PDU（含 multipart 体） |
| 取回确认 | MS→MMSC `POST` | m-acknowledge-ind PDU |
| 递送报告（回放） | MMSC→MS 方向连接 `POST` | m-delivery-ind PDU |
| 读取报告 | MS→MMSC `POST` | m-read-rec-ind PDU |

规则：所有承载 MMSE PDU 的请求/响应 **Content-Type 恒为 `application/vnd.wap.mms-message`**（WAP-209 §5）；**HTTP 200 ≠ MMS 业务成功**——业务状态在 PDU 的 X-Mms-Response-Status / X-Mms-Status 字段（§3.7），必须分开断言；keep-alive 连接上多事务按 Content-Length 分隔，PDU 边界 = body 边界。

### 3.2 PDU 结构总则（WAP-209 §5、§7）

MMS PDU = `mms-headers [message-body]`。消息体只在 m-send-req 与 m-retrieve-conf 出现（§5 "The message body is used only when the multimedia message is sent or retrieved. All other PDUs contain only the mms-headers part"）。头部顺序规则（§7 原文）："the order of the fields is not significant, **except that Message-Type, Transaction-ID and MMS-Version MUST be at the beginning of the message headers, in that order**, and **the content type MUST be the last header, followed by message body**"：

```
PDU = 8C <msg-type-octet>                      ; offset 0-1 固定
      98 <Transaction-ID Text-string>          ; offset 2 起固定次序
      8D <version short-integer>
      <其余头字段，任意序，可重复（如多个 To）>
      [ 84 <Content-type-value> <message-body> ]  ; 仅 m-send-req / m-retrieve-conf
```

未知消息类型必须丢弃（§7.2.14 "Unknown message types will be discarded"）——本生成器将其实现为 planner 拒绝（负例 §7）。头部解析循环以 Content-Type 字段码（0x84）或 PDU 末尾终止；每个字段 = 字段码（1 字节 Short-integer，值 = 0x80 | 表 8 编号）+ 值（编码原语见 §3.3）。

### 3.3 编码原语（WAP-209 §7.1 + WAP-230-WSP §8.4.1；tshark 3.6.14 实测一致）

| 原语 | 编码规则 | 宽度 | 端序 |
|---|---|---|---|
| Short-integer | 单字节 `0x80 \| v`，v ∈ 0–127 | 1B | — |
| Long-integer | 长度字节 n（1–30）+ n 字节值 | 1+n B | **大端** |
| Integer-value | Short-integer \| Long-integer | 变长 | — |
| Uintvar | 7bit 一组，**低组在前**，除最后一组外高位置 1 | 1–5B | 小组序（LSB 组先） |
| Value-length | 值长 ≤30：单字节长度；>30：`0x1F` + Uintvar | 1 / 2+ B | — |
| Text-string | [`0x7F` Quote，仅当首字符为分隔符时] ASCII 字节 + `0x00` 终止 | 变长 | — |
| Encoded-string-value | Text-string **或** `Value-length Char-set Text-string`（Char-set = Short/Long-integer MIBEnum 值；106=UTF-8，1000=UCS-2）（§7.2.9） | 变长 | — |
| Date-value | Long-integer，1970-01-01 GMT 起的秒（§7.2.5） | 1+4B | 大端 |
| Absolute/Relative token | Absolute=`0x80`、Relative=`0x81`，用于 Expiry/Delivery-Time/Reply-Charging-Deadline（§7.2.7/§7.2.10） | 1B | — |

生成器约束：Long-integer 仅产生 1–4 字节（tshark mmse 解码器上限 4B，超长属非法配置进负例）；Uintvar ≤ 4B 有效载荷（≤ 2^28，超长触发 tshark `mmse.oversized_uintvar` expert，生成器按负例拒绝）；charset 本版恒产生 106（UTF-8），其余 MIBEnum 值不产生（§1 声明）。

**Long-integer 定宽补零策略**：**Date-value 恒 4B**（Date 字段与 Expiry/Delivery-Time 绝对形态的内层日期值）、**Delta-seconds 恒 3B**（Expiry/Delivery-Time 相对形态的秒数）、**Message-Size 恒 3B**；值不足该宽度时高位补零（如 4800 = 0x0012C0 → `00 12 c0`；921600 = 0x0E1000 恰满 3B → `0e 10 00`），超出时向上取最小可容纳宽度（4B 封顶）。与 WSP **最小编码**的区别：WSP 允许长度字节取 1–30 任意值（前导零字节可省，4800 最小编码仅 2B `12 c0`，同样合法、解码值相同）；选择定宽是为了 frames hex 逐字节断言的字节形态稳定（用例 `mmse_encoding_long_integer` 断言 `8e 03 00 12 c0` 精确字节、用例 `mmse_notification_ind` 断言 Expiry `88 05 81 03 0e 10 00`）。本版不产生最小编码形态；长度字节必须如实声明实际字节数（=0 或 >4 按长度负例拒绝，§7）。

### 3.4 头字段代码与逐字段规格（WAP-209 §7.3 表 8：Assigned Number；线码 = `0x80 | 编号`）

| 线码 | 字段 | 值编码 | 值域 / 默认 | 出现 PDU（必选性） | 出处 |
|---:|---|---|---|---|---|
| 0x8C | X-Mms-Message-Type | 单字节枚举 | §3.7 表 | 全部（M） | §7.2.14 |
| 0x98 | X-Mms-Transaction-ID | Text-string | 唯一标识；规范无长度上界，**生成器策略上界 32B** | 全部（仅 m-delivery-ind 无此字段；retrieve-conf 中为必选，WAP-209 §7.3 表 5 标注 M） | §7.2.26、表 5 |
| 0x8D | X-Mms-MMS-Version | Short-integer（高 nibble 主版本 1–7、低 nibble 次版本 0–14；仅主版本时低 nibble=15） | 0x10=1.0、0x13=1.3；本版默认 1.2（线码 0x92） | 全部（M） | §7.2.16 |
| 0x85 | Date | Long-integer（秒） | — | send-req O / retrieve-conf M / delivery-ind M | §7.2.5、表 1/5/7 |
| 0x89 | From | `Value-length (0x80 Address-present-token Encoded-string-value \| 0x81 Insert-address-token)` | insert-token=1B 值体 | send-req M / notification O / retrieve-conf O | §7.2.11 |
| 0x97 | To | Encoded-string-value | §8 地址模型 | send-req O（To/Cc/Bcc 至少一）/ retrieve-conf O / delivery-ind M | §7.2.25 |
| 0x82 | Cc | Encoded-string-value | 同 To | send-req O / retrieve-conf O | §7.2.2 |
| 0x81 | Bcc | Encoded-string-value | 同 To | send-req O | §7.2.1 |
| 0x96 | Subject | Encoded-string-value | — | send-req O / notification O / retrieve-conf O | §7.2.24 |
| 0x8A | X-Mms-Message-Class | `0x80 Personal \| 0x81 Advertisement \| 0x82 Informational \| 0x83 Auto \| Token-text` | 缺省按 Personal 解释 | send-req O / notification M / retrieve-conf O | §7.2.12 |
| 0x88 | X-Mms-Expiry | `Value-length (0x80 Date-value \| 0x81 Delta-seconds)` | 缺省 maximum | send-req O / notification **M（仅 interval 形态）** | §7.2.10、表 1/3 |
| 0x87 | X-Mms-Delivery-Time | 同 Expiry 形态 | 缺省 immediate | send-req O | §7.2.7 |
| 0x8F | X-Mms-Priority | `0x80 Low \| 0x81 Normal \| 0x82 High` | 缺省 Normal | send-req O / retrieve-conf O | §7.2.17 |
| 0x94 | X-Mms-Sender-Visibility | `0x80 Hide \| 0x81 Show` | 缺省 Show | send-req O | §7.2.22 |
| 0x86 | X-Mms-Delivery-Report | `0x80 Yes \| 0x81 No` | — | send-req O（class=Auto 时必为 No）/ retrieve-conf O | §7.2.6 |
| 0x90 | X-Mms-Read-Reply（1.1+ 更名 X-Mms-Read-Report） | `0x80 Yes \| 0x81 No` | — | send-req O / retrieve-conf O | §7.2.18、OMA-MMS-ENC 1.1 |
| 0x91 | X-Mms-Report-Allowed | `0x80 Yes \| 0x81 No` | 缺省 Yes | notifyresp O / acknowledge O | §7.2.19 |
| 0x92 | X-Mms-Response-Status | 单字节枚举 | §3.7 表 | send-conf **M** | §7.2.20 |
| 0x93 | X-Mms-Response-Text | Encoded-string-value | — | send-conf O | §7.2.21 |
| 0x8B | Message-ID | Text-string（RFC 822 msg-id，**不含 `<` `>`**） | MMSC 生成，全局唯一 | send-conf（接受时 M）/ retrieve-conf O（Read-Reply=Yes 时 M）/ delivery-ind M | §7.2.13 |
| 0x8E | X-Mms-Message-Size | Long-integer（字节） | — | notification M | §7.2.15 |
| 0x83 | X-Mms-Content-Location | Text-string（URI） | 如 `http://mmsc/message-id` | notification M | §7.2.3 |
| 0x95 | X-Mms-Status | 单字节枚举 | §3.7 表 | notifyresp M / delivery-ind M | §7.2.23 |
| 0x9B | X-Mms-Read-Status | `0x80 Read \| 0x81 Deleted-without-being-read` | — | read-rec-ind M | OMA-MMS-ENC 1.1 |
| 0x84 | Content-Type | WSP Content-type-value（§3.6） | — | send-req M / retrieve-conf M（**必须最后**） | §7.2.4 |
| 0x99/0x9A | X-Mms-Retrieve-Status / -Text | 枚举 / Encoded-string-value | §3.7 表 | retrieve-conf（1.1+，本版不产生） | OMA-MMS-ENC 1.1 |
| 0x9C–0x9F | X-Mms-Reply-Charging 族 | — | — | 本版不产生（边界，§1） | OMA-MMS-ENC 1.1 |
| — | Application-header | `Token-text Application-specific-value`（RFC 822 扩展头） | — | 各 PDU O（本版不产生，§1 声明） | §7.1 |

**tshark 显示名注意**（实测，tshark 3.6.14）：PDU 携带 0x90 头且 MMS-Version 显式 ≥1.1（线码 0x91+）时字段显示为 `mmse.read_report`；仅在版本头缺失（tshark 默认按 1.0）时显示 `mmse.read_reply`。本版 fixture 恒携带版本头（1.2），断言一律用 `mmse.read_report`。

### 3.5 PDU 逐个规格（字段集与总长度公式；必选性出自 WAP-209 表 1–7）

**总长公式口径（先读）**：下列每条公式给出**必选集最小长度** `L_min`，逐项宽度按 §3.3 编码原语精确到字节；可选头出现时按下面的"字段宽度速查"累加——公式即逐字节可复算（工作例：§6 配置的通知事件 PDU = **99B**，见 m-notification-ind 条）。**字段宽度速查**（宽度含 1B 字段码）：

- 固定 **2B**：Message-Type、MMS-Version、Message-Class（well-known 形态）、Priority、Sender-Visibility、Delivery-Report、Read-Reply、Report-Allowed、Response-Status、Status、Read-Status；
- **2+len(s)**：Transaction-ID、Message-ID、Content-Location、Subject（裸形态）、Response-Text（裸形态）、To/Cc/Bcc（每实例）——字段码 1B + Text-string(s + NUL)；
- **4+len(s)**：From 地址形态（`89` + Value-length + `80` + s + NUL）、Subject VL+charset 形态（`96` + Value-length + charset 1B + s + NUL）；
- **3B**：From insert-address-token 形态（`89 01 81`）；
- **4+n**：Expiry、Delivery-Time（`88`/`87` + Value-length + token 1B + Long-integer(1+n)，n = 值字节数；按 §3.3 定宽策略：绝对形态恒 n=4、相对形态恒 n=3）；
- **2+n**：Date（`85` + Long-integer(1+n)，恒 n=4）、Message-Size（`8e` + Long-integer(1+n)，恒 n=3）；
- **Content-Type**：`1 + len(Content-type-value)`；Content-type-value = 单媒体码 1B（无参数）或 `Value-length + (媒体码 + 参数集)`（multipart/带参数，§3.6）。

**m-send-req（0x80，表 1）**：必选 = Message-Type / Transaction-ID / MMS-Version / From /（To|Cc|Bcc 至少一）/ Content-Type；可选 = Date / 其余地址 / Subject / Message-Class / Expiry / Delivery-Time / Priority / Sender-Visibility / Delivery-Report / Read-Reply。事务 ID 由发送客户端创建，仅在发送事务内唯一（§6.1）。`L_min = 2 + (2+len(tid)) + 2 + (4+len(from)) + (2+len(addr₁)) + (1 + CT-value长) + len(body)`（From 地址形态；insert-token 形态 From 项改 3B；地址可 To/Cc/Bcc 多实例，每实例按 `2+len(addr)` 累加；其余可选头按速查累加）。

**m-send-conf（0x81，表 2）**：必选 = Message-Type / Transaction-ID / MMS-Version / Response-Status；可选 = Response-Text / Message-ID（**接受消息时必须出现**，§6.1.2）。无消息体。`L_min = 2 + (2+len(tid)) + 2 + 2`；可选累加：Response-Text（裸形态 `2+len(text)`）、Message-ID（`2+len(msgid)`）。

**m-notification-ind（0x82，表 3）**：必选 = Message-Type / Transaction-ID（MMSC 创建，至后续 M-NotifyResp 唯一）/ MMS-Version / Message-Class / Message-Size / Expiry（**仅 interval 形态**）/ Content-Location；可选 = From / Subject。无消息体。`L_min = 2 + (2+len(tid)) + 2 + 2 + (2+n_size) + (4+n_delta) + (2+len(uri))`；可选累加：From（地址形态 `4+len(addr)`｜insert-token 3B）、Subject（裸 `2+len(s)`｜charset 形态 `4+len(s)`）。**工作例**（§6 fixture 通知事件，= 用例 `mmse_notification_ind`；TID=`MMSC-N-0007` 11B、From=24B、Size=4800 定宽 3B、Expiry interval 921600=0x0E1000 定宽 3B、URI 38B、无 Subject）：2 + 13 + 2 + 2 + 5 + 7 + 40 = 71（必选集）+ 28（From 地址形态）= **99B**。

**m-notifyresp-ind（0x83，表 4）**：必选 = Message-Type / Transaction-ID / MMS-Version / Status（Retrieved 只能在成功取回后使用）；可选 = Report-Allowed。无消息体。`L_min = 2 + (2+len(tid)) + 2 + 2`；可选累加：Report-Allowed 2B。

**m-retrieve-conf（0x84，表 5）**：必选 = Message-Type / **Transaction-ID（必选——WAP-209 §7.3 表 5 标注 Mandatory；立即取回复用通知 TID（§6.3），延迟取回可另起新 TID（§6.2/§6.4））** / MMS-Version / Date / Content-Type；可选 = Message-ID（发起方要求 Read-Reply 时必须出现）/ From / To / Cc / Subject / Message-Class / Priority / Delivery-Report / Read-Reply。带消息体。`L_min = 2 + (2+len(tid)) + 2 + (2+n_date) + (1 + CT-value长) + len(body)`；可选按速查累加。

**m-acknowledge-ind（0x85，表 6）**：必选 = Message-Type / Transaction-ID（**取自紧邻的前一个 M-Retrieve 操作**）/ MMS-Version；可选 = Report-Allowed。无消息体。`L_min = 2 + (2+len(tid)) + 2`；可选累加：Report-Allowed 2B。

**m-delivery-ind（0x86，表 7）**：必选 = Message-Type / MMS-Version / Message-ID / To / Date / Status；**无 Transaction-ID**、**无响应消息**（§6.5 "There is no response message to the delivery report"——HTTP 层 200 仅为传输确认）。`L_min = 2 + 2 + (2+len(msgid)) + (2+len(to)) + (2+n_date) + 2`。

**m-read-rec-ind（0x87，OMA-MMS-ENC 1.1）**：必选 = Message-Type / Transaction-ID / MMS-Version / Message-ID / X-Mms-Read-Status。`L_min = 2 + (2+len(tid)) + 2 + (2+len(msgid)) + 2`。MMS 1.0 等价物是 Message-Class=Auto 的新消息（WAP-209 §6.6）；1.1+ 用独立 PDU。

### 3.6 multipart 消息体（WAP-209 §5 + WAP-230-WSP §8.5.3；RFC 2387）

消息体 = WSP 二进制 multipart（**长度定界，无 boundary 字符串**——MIME boundary 仅是 RFC 2046 文本形态概念，二进制编码不需要）：

```
message-body = Uintvar(partNum)
               *( Uintvar(headersLen) Uintvar(dataLen) part-headers part-data )
part-headers = Value-length( Content-type-value [参数] ) [WSP 头：0xC0 Content-ID | 0x8E Content-Location …]
```

Content-Type 头（线码 0x84）值 = `Value-length ( Short-integer(媒体码) *(参数) )`；multipart/related 的媒体码 = `0xB3`（= 0x80|0x33）。参数（typed，线码 = `0x80|参数码`）：`0x89` type（multipart/related 的 type 参数，值为 Constrained-encoding：Extension-media 文本或 Short-integer 媒体码）、`0x8A` start（指向根部件 Content-ID，RFC 2387；WAP-209 §6.1.1 "Start parameter … MUST point to the presentation part"，缺省时演示部件必须是第一个 part）；part 头内参数：`0x85` name（Text-string）、`0x81` charset（Short-integer MIBEnum，106=UTF-8）。

part 的 Content-type-value：有 WSP 媒体码的用 Short-integer——text/plain=`0x83`、image/jpeg=`0x9E`、image/gif=`0x9D`、image/png=`0xA0`；无码的（**application/smil、audio/\* 等**）用 Extension-media 文本（如 `"application/smil" 0x00`）。附件 part 头：`0xC0` Content-ID（RFC 2392 形态，AOSP 实现带 `<` `>` 角括号）、`0x8E` Content-Location（文件名）。SMIL 根部件引用文本/图片/音频 part 的 Content-ID/Content-Location。

**长度自洽不变式**（validator 逐条校验，负例 §7）：`headersLen` 覆盖 part 头全部字节（含 Value-length 前缀）；`dataLen` = part 数据字节数；`Σ` 各 part 累计 + len(Uintvar(partNum)) = body 总长 = HTTP `Content-Length` − PDU 头部长。**部件数上界**：本版 partNum ≤ 127（此时 Uintvar 恒 1B，上式即"+1"；>127 的配置按 §7 长度错归口拒绝）。start 参数引用的 Content-ID 必须存在于某 part 头。

### 3.7 值域与状态码（WAP-209 §7.2；MMS 1.1/1.2 扩展值出自 OMA-MMS-ENC，tshark 值表一致）

**X-Mms-Message-Type**（§7.2.14）：0x80 m-send-req、0x81 m-send-conf、0x82 m-notification-ind、0x83 m-notifyresp-ind、0x84 m-retrieve-conf、0x85 m-acknowledge-ind、0x86 m-delivery-ind、0x87 m-read-rec-ind、0x88 m-read-orig-ind（1.1）、0x89 m-forward-req、0x8A m-forward-conf（1.1）、0x8B–0x93 m-mbox 系列（1.2，本版不产生）。

**X-Mms-Response-Status**（§7.2.20；注意与 X-Mms-Status 是**不同字段**——任务口径中"X-Mms-Status: 128 Ok/129 Error"实为 Response-Status 值域，已更正）：0x80 Ok、0x81 Error-unspecified、0x82 Error-service-denied、0x83 Error-message-format-corrupt、0x84 Error-sending-address-unresolved、0x85 Error-message-not-found、0x86 Error-network-problem、0x87 Error-content-not-accepted、0x88 Error-unsupported-message；1.1+ 瞬态 0xC0–0xC4（Transient failure / Sending address unresolved / Message not found / Network problem / Partial success）；1.1+ 永久 0xE0–0xEA（Permanent failure / Service denied / Message format corrupt / Sending address unresolved / Message not found / Content not accepted / Reply charging limitations not met / Reply charging request not accepted / Reply charging forwarding denied / Reply charging not supported / 1.2: Address hiding not supported）。"Any other values SHALL NOT be used"（§7.2.20）。

**X-Mms-Status**（§7.2.23）：0x80 Expired、0x81 Retrieved、0x82 Rejected、0x83 Deferred、0x84 Unrecognised（仅版本管理用）；1.1+：0x85 Indeterminate、0x86 Forwarded；1.2：0x87 Unreachable。

**X-Mms-Read-Status**（1.1）：0x80 Read、0x81 Deleted-without-being-read。**X-Mms-Priority**（§7.2.17）：0x80/0x81/0x82 = Low/Normal/High。**Message-Class**（§7.2.12）：0x80–0x83 = Personal/Advertisement/Informational/Auto（Auto 时不得请求 Delivery-Report/Read-Report，表 1）。**Yes/No 族**：0x80/0x81。**Sender-Visibility**：0x80 Hide / 0x81 Show。

**地址模型**（§8，ABNF）：`address = e-mail | device-address`；`device-address = 值 "/TYPE=" 类型`，类型 ∈ {PLMN（`["+"] 1*(DIGIT ["-"/"."])`）、IPv4、IPv6、WINA 注册扩展}；e-mail 按 RFC 822。示例：`+358501234567/TYPE=PLMN`、`195.153.199.30/TYPE=IPv4`、`FEDC:BA98:7654:3210:FEDC:BA98:7654:3210/TYPE=IPv6`、`Joe User <joe@user.org>`。

**版本互操作**（§6.7）：同主版本仅次版本差异 → 忽略不识别字段/值；未知 PDU → Proxy-Relay 以 m-send-conf(Error-unsupported-message) 响应、终端以 m-notifyresp-ind(Unrecognised) 响应；不同主版本不保证兼容。**接收侧行为显式不适用**：本版生成器为声明式回放（§4 定性），两端 PDU 均由配置显式声明，**不实现接收侧反应性互操作**——对未知 PDU 的 m-send-conf(Error-unsupported-message) 应答、m-notifyresp-ind(Unrecognised) 应答、忽略不识别字段后继续处理，均不进入本版用例与实现范围；本条仅作规范行为出处记录。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性声明**：本引擎对 MMSE 采用**声明式脚本化回放**——配置是剧本（sessions[]/events[] 逐条声明两端 PDU），引擎是回放者，按序产出帧；"事件驱动"一词不用于定性整体行为，仅用于两处反应性成分：①自动应答（HTTP 传输层收到请求帧自动补状态行/头/Content-Length 的响应骨架——PDU 内容仍由事件显式声明）；②连接边界（事件序列中源端口/角色切换触发新 TCP 连接，多会话展开）。

| 现网场景（WAP-206 §6 事务流） | 事务交互 | 驱动顺序 | 对应用例 |
|---|---|---|---|
| ① 提交彩信（Figure 3：发送方 UA→MMSC） | POST m-send-req(T1)→200 m-send-conf(T1, status, MsgID) | UA 驱动 | `mmse_send_req_ipv4`、`mmse_send_conf_ok`、`mmse_send_conf_error` |
| ② 立即取回（Figure 4：取回先于通知确认，无 M-NotifyResp） | 通知(t2)→GET Content-Location→200 m-retrieve-conf(复用 t2) | MMSC 推通知（回放）→ UA GET | `mmse_notification_ind`、`mmse_retrieve_conf_immediate` |
| ③ 延迟取回（Figure 5：通知→确认→时延→GET→conf→ack） | 通知(t3)→POST m-notifyresp(t3, Deferred)→GET→200 m-retrieve-conf(新 TID)→POST m-acknowledge(新 TID) | MMSC 通知（回放）→UA 确认→UA GET→MMSC conf→UA ack | `mmse_notifyresp_deferred`、`mmse_acknowledge_ind` |
| ④ 递送报告链（Figure 3 尾：MMSC→发送方） | POST m-delivery-ind(MsgID, To, Date, Status) | MMSC 驱动（回放），MsgID 关联 ① 的 send-conf | `mmse_delivery_ind_retrieved`、`mmse_delivery_ind_expired` |
| ⑤ 读取报告链（§6.6 + 1.1 PDU） | POST m-read-rec-ind(MsgID, Read-Status)→200 | 接收方驱动，MsgID 关联被读消息 | `mmse_read_rec_ind`、`mmse_read_status_deleted` |
| ⑥ 长连接多事务（现网 MMSC 会话复用） | 同连接 提交→取回→确认 严格配对 | 事件编排，无 pipelining | `mmse_http_keepalive_multi_transaction` |
| ⑦ 多终端并行（发送方+接收方并行、多 UA） | 独立四元组各自全链 | 多会话展开 | `mmse_multi_session` |

**五层覆盖逐层结论**：功能层——8 类 PDU 各一正例（m-send-req/m-send-conf 双分支/notification/notifyresp/retrieve-conf/acknowledge/delivery-ind/read-rec-ind），每类错误分支负例（§7：配置/线格式/状态机/关联/长度/值域 11 条）。性能层——大 multipart 跨 MSS 分段重组（`mmse_mss_large_multipart`）、Value-length>30 的 0x1F+Uintvar 形态、Long-integer 3B/4B、附件尺寸上界。数据场景层——Response-Status 两值例（Ok / Error-service-denied）、Status **实测三值**（Retrieved / Expired / Deferred；Rejected / Unrecognised 及 1.1+ 值本版不产生、不构成本版覆盖声明，§1）、Read-Status 两值、Message-Class 四值、Priority **实测两值**（Normal 基线 / High 可选头例）、Sender-Visibility 两值（Show 基线 / Hide 可选头例）、Yes/No 族、版本号 1.2 编码、编码变体（Text-string 裸 / VL+charset / Quote 三形态、From 地址 / insert-token 两形态、绝对相对时间、地址四形态；空串 / Application-header 扩展头 / charset 高值本版不产生，§1 声明）、非法值拒绝。地址与流层——IPv4/IPv6 独立 fixture、单流基线、多会话双四元组；**流关联（控制流派生数据流）显式不适用**：MM1 消息体在带内（multipart 在 PDU body 内传输），无控制流派生媒体/数据流，WAP-209/WAP-206 全文无流关联概念；**多流（会话内部并发流）显式不适用**：本版仅 HTTP/1.1，单连接内请求/响应严格配对（RFC 7230 §6.3），无并发流概念。业务层——提交/立即取回/延迟取回/递送报告/读取报告全链、长连接多事务、多终端并行均为现网日常（AOSP 事务服务同款流程），优先于教科书全 PDU 遍历。

## 5. 消息/事务模型与状态机

**事务定义**（WAP-206 §6/§7）：MM1 事务 = 一次逻辑独立的 PDU 交互，共四类——发送（M-Send.req↔M-Send.conf）、通知（M-Notification.ind→M-NotifyResp.ind）、取回（GET→M-Retrieve.conf→M-Acknowledge.ind）、递送报告（M-Delivery.ind，无响应 PDU）。**关联标识取材规则**（逐对）：send-req↔send-conf 同 Transaction-ID（发送客户端创建，§6.1）；notification→notifyresp 同 Transaction-ID（MMSC 创建，§6.2）；延迟取回时 MMSC **可**另起新 Transaction-ID（§6.2/§6.3），retrieve-conf↔acknowledge 同该新 ID（§6.4 "originates from immediately previous M-Retrieve operation"）；立即取回（无 notifyresp）时 retrieve-conf 复用通知 ID（§6.3）；delivery-ind / read-rec-ind 经 **Message-ID** 关联 send-conf 的 Message-ID（§6.1.2/§6.5——"enables a client to match delivery reports with previously sent messages"），不经 Transaction-ID。**多事务** = 一个 TCP 连接内多笔事务按序执行（keep-alive，请求/响应严格交替，无 pipelining）；**事务交互** = 延迟取回链（notifyresp 必须先于 GET；acknowledge 必须在 retrieve-conf 之后）与 Message-ID 跨事务回指（delivery-ind 依赖先前 send-conf 已分配 Message-ID）。

会话状态机（每事件编排会话，HTTP/1.1 承载）：

| 状态 | 允许事件 | 必须保持 |
|---|---|---|
| `ConnectPending` | TCP 三次握手完成 | 握手后首帧为 HTTP 请求（POST/GET）或本会话首事件方向与声明一致 |
| `RequestSent` | 发送承载 PDU 的请求 | Content-Type=application/vnd.wap.mms-message、Content-Length=PDU 字节数；GET 无 body |
| `ResponsePending` | 收到 HTTP 响应 | 200 的 body 恰为一个合法 PDU；响应 PDU 的 Transaction-ID/Message-ID 按取材规则对应请求侧 |
| `KeepAlive`（多事务） | 下一笔事务请求 | 请求/响应严格交替；每笔事务独立 TID；不得跨事务复用 TID/MsgID |
| `Terminating` | FIN 挥手 | 全部事件完成后才挥手 |
| `Closed` | TCP FIN | 关闭后不得产生新业务帧 |

**确定性**：同一配置必然产出同一字节序列（Transaction-ID/Message-ID/日期为配置显式值或带 seed 的策略值；无墙钟依赖）。

**自动派生规则**（引擎自动补出的内容，逐条）：①`http` 层自动补 HTTP 请求行/状态行与通用头（Host/Content-Type/Content-Length/Connection），Content-Length 恒等于 PDU/multipart 编码后字节数；头可被事件 `http` 子映射覆盖。②`mmse` 层按 §3.2 顺序规则自动排序首三头（Message-Type/Transaction-ID/MMS-Version）并把 Content-Type 置于最后。③取回事务的 GET URI 自动取自通知事件的 content_location 字段（配置内引用，非跨会话隐式状态）。④连接边界：事件序列中源端口/角色变化触发新 TCP 连接；多会话展开第二会话包号起点 = 前会话总包数 + 1。并发会话（`concurrent: true`）本版不适用——MM1 各事务独立短连接即可表达，双会话用多会话展开。

## 6. 配置 typedef（JSON 形状示例，非 Go 代码）

```json
{
  "layers": [{"tcp": {}}, {"http": {}}, {"mmse": {}}],
  "src_ip": "192.0.2.71", "dst_ip": "198.51.100.71",
  "mmse": {
    "profile": "mmse_http_v1",
    "mms_version": "1.2",
    "sessions": [
      {
        "role": "ua", "src_port": 40710, "dst_port": 80,
        "events": [
          { "kind": "send_req", "transaction_id": "AB7261192206",
            "date": 1782952800,
            "from": {"address": "+8613800138000/TYPE=PLMN"},
            "to": [{"address": "+8613911223344/TYPE=PLMN"}],
            "subject": {"text": "MMSE check", "charset": 106},
            "message_class": "personal", "priority": "normal",
            "expiry": {"relative": 921600}, "delivery_time": null,
            "sender_visibility": "show",
            "delivery_report": true, "read_reply": true,
            "content": { "kind": "multipart_related",
              "start": "<smil.smil>", "type": "application/smil",
              "parts": [
                { "content_type": "application/smil", "content_id": "<smil.smil>",
                  "data_b64": "PHNtaWw+Lj4uLg==" },
                { "content_type": "text/plain", "charset": 106, "name": "text_1.txt",
                  "content_id": "<text_1.txt>", "content_location": "text_1.txt",
                  "data": "Hello MMSE world" },
                { "content_type": "image/jpeg", "name": "image_1.jpg",
                  "content_location": "image_1.jpg", "data_b64": "/9j/4AAQ" } ] } },
          { "kind": "send_conf", "transaction_id": "AB7261192206",
            "response_status": "Ok", "response_text": null,
            "message_id": "mmsc-msg-20260901-0001" }
        ]
      },
      {
        "role": "mmsc", "src_ip": "198.51.100.71", "dst_ip": "192.0.2.72",
        "src_port": 40711, "dst_port": 80,
        "events": [
          { "kind": "notification_ind", "transaction_id": "MMSC-N-0007",
            "from": {"address": "+8613900139000/TYPE=PLMN"}, "subject": null,
            "message_class": "personal", "message_size": 4800,
            "expiry": {"relative": 921600},
            "content_location": "http://mmsc.example/mms/MSG20260901001" }
        ]
      },
      {
        "role": "ua", "src_ip": "192.0.2.72", "dst_ip": "198.51.100.71",
        "src_port": 40712, "dst_port": 80,
        "events": [
          { "kind": "notifyresp_ind", "transaction_id": "MMSC-N-0007",
            "status": "Deferred", "report_allowed": true }
        ]
      }
    ],
    "wire_fault": ""
  }
}
```

形状要点：`sessions[]` = 统一术语的**事件编排会话**（每个自带四元组与角色 `ua`/`mmsc` 及事件序列；多会话展开按序整块回放，第二会话包号起点 = 前会话总包数 + 1）；`events[]` = 会话的**事件序列**，元素为一笔 MM1 事务一侧的 PDU（kind 覆盖 send_req / send_conf / notification_ind / notifyresp_ind / retrieve（GET，引擎自动从引用的通知事件取 content_location）/ retrieve_conf / acknowledge_ind / delivery_ind / read_rec_ind）；上例含三个会话：UA 提交链、MMSC 方向 `mmsc` 会话回放 m-notification-ind（§1 回放语义）、`ua` 会话 POST m-notifyresp-ind（AOSP NotifyRespTransaction 同款方向）；响应侧 PDU 内容同样显式声明（声明式），HTTP 传输骨架由 `http` 层自动补齐（自动应答反应性成分）；`from` 支持 `{"address": ...}` 与 `{"insert_token": true}` 两形态（§3.4 From）；`expiry`/`delivery_time` 支持 `{"relative": 秒}` 与 `{"absolute": epoch}`；`mms_version` 默认 "1.2"；`wire_fault` 仅负例注入口（取值见 §7），不得成为线上字段。**Transaction-ID 策略上界 32B**（WAP-209 无规范上界，此为生成器策略，validator 强制）。通知事件即用例 `mmse_notification_ind` fixture：其 PDU 逐字节复算 = **99B**（§3.5 工作例），HTTP Content-Length 恒等于该值。

## 7. 错误处理（负例锚词表）

以下输入必须由 planner/validator 拒绝并传播为 task error（任务错误），不得产出成功 PCAP、`completed/0 packet` 或仅 TCP/HTTP 外壳的假成功。锚词（anchor word）为 `error_contains` 断言字面值，与用例文档 §5 一一对应：

| 负例 ID | 故障输入（方向） | `error_contains` 候选锚词 |
|---|---|---|
| `mmse_neg_carrier_config` | 配置错：层链缺 http（tcp→mmse 直连）、承载 Content-Type 非 application/vnd.wap.mms-message、端口/载体矛盾、profile 未定义值 | `carrier`、`content-type`、`layer` 或 `port` |
| `mmse_neg_pdu_head_order` | 线格式错：首三头缺序（如 Transaction-ID 先于 Message-Type、MMS-Version 缺失）、首字段非 0x8C | `order`、`header` 或 `message-type` |
| `mmse_neg_unknown_pdu_type` | 线格式/值域错：X-Mms-Message-Type 值未分配（0x00–0x7F 或 >0x93），**或已分配但本版不产生值（0x88–0x93，§1 边界）——两类同归口本行** | `message-type`、`unknown` 或 `pdu` |
| `mmse_neg_missing_content_type` | 线格式错：m-send-req/m-retrieve-conf 缺最后的 Content-Type 头；无体 PDU（notification/notifyresp/acknowledge/delivery/read-rec）声明了 content 或 Content-Type | `content-type` 或 `body` |
| `mmse_neg_multipart_structure` | 线格式错：headersLen/dataLen 越界（超出 body 剩余字节）、partNum=0 但声明了 parts、partNum 与实际 part 数不符、start 参数引用不存在的 Content-ID（§5 MUST 规则） | `multipart`、`part` 或 `start` |
| `mmse_neg_mandatory_missing` | 必选缺失：send-req 的 To/Cc/Bcc 全缺或 From 缺失；notification 缺 Message-Class/Message-Size/Expiry/Content-Location；send-conf 缺 Response-Status；delivery-ind 缺 Message-ID/To/Date/Status | `mandatory`、`missing` 或 `field` |
| `mmse_neg_tid_correlation` | 关联错：send-conf/notifyresp/acknowledge 的 Transaction-ID 与对应请求不一致（§5 取材规则） | `transaction`、`correlation` 或 `match` |
| `mmse_neg_msgid_correlation` | 关联错：delivery-ind / read-rec-ind 的 Message-ID 无来源 send-conf（跨事务回指断裂） | `message-id`、`correlation` 或 `match` |
| `mmse_neg_sequence` | 状态机错：acknowledge 先于 retrieve、notifyresp 无前置 notification、send-conf 无前置 send-req、同一连接响应与请求顺序违反严格配对 | `sequence`、`state` 或 `order` |
| `mmse_neg_length` | 长度错：HTTP Content-Length ≠ PDU 编码字节数、Long-integer 长度字节 >4 或 =0、Uintvar >4B 载荷、Value-length 与实际值长不符、Transaction-ID >32B（策略上界） | `length`、`uintvar` 或 `overflow` |
| `mmse_neg_value_range` | 值域错：Priority/Status/Response-Status/Message-Class/Read-Status/Yes-No 族取未定义值（如 priority=0x83、status=0x8F）；**Reply-Charging 字段族（0x9C–0x9F）或本版不产生编码形态（空串 / Application-header / charset≠106，§1 声明）出现在配置——同归口本行** | `value`、`range` 或 `status` |

**不得误报为 planner error 的合法协议事件**：m-send-conf 错误 Response-Status（业务错误响应是正例形态，`mmse_send_conf_error`）、m-delivery-ind Status=Expired（过期是合法状态值）、m-notifyresp Deferred（延迟取回合法路径）、From insert-address-token（1B 合法形态，正例 `mmse_from_insert_token`）、Text-string Quote 形态（首字符分隔符前置 0x7F，正例 `mmse_text_string_quote`）、MMS 1.0/1.1 混用（§6.7 同主版本互通，但本版 fixture 统一 1.2）、To/Cc/Bcc 多实例（任意数量合法）。**接收侧互操作反应不进用例也不进负例**（§3.7 显式不适用声明）；Application-header / 空串 / charset 高值已按 §1 声明归口 `mmse_neg_value_range` 拒绝，不再列为本条合法事件。只有配置、线格式、长度、值域或关联错误进入负例。

## 8. 边界

- **大消息跨 MSS**：multipart 附件使 PDU 超过 MSS 时按 `http` 层 MSS 规则分多个 TCP 段（段数 = ceil(帧长/MSS)）；断言必须按 `tcp.stream` 重组后核对 Content-Length 自洽与 PDU 完整性；**分段边界不是 PDU/multipart 边界**。`mmse_mss_large_multipart` 用 ≥3 段（MSS 压至 536）。
- **数值上界**：Long-integer 生成器 1–4B（**定宽补零策略见 §3.3**：Date-value 恒 4B、Delta-seconds 与 Message-Size 恒 3B，Date 4B 满 0xFFFFFFFF 合法）；Message-Size 最大 4B；Uintvar ≤4B 载荷（2^28）；Value-length 短形态 ≤30、长形态 0x1F+Uintvar；Transaction-ID 策略上界 32B（规范无上界，显式策略）；multipart 部件数上界 127（§3.6）。
- **枚举边界**：Yes/No 族只有 0x80/0x81 两值；Priority/Class/Read-Status/Status/Response-Status 值域见 §3.7，域外值属负例（"Any other values SHALL NOT be used"，§7.2.20）。
- **文本边界**：Text-string 首字符为分隔符（RFC 822 分隔符集：`( ) < > @ , ; : \ " / [ ] ? =` 与空格/HTAB）时必须前置 0x7F Quote；空串（仅 0x00 终止）协议合法但本版不产生（§1 声明）；charset 编码形态仅 MIBEnum 整数，本版仅产生 106（§1 声明）。
- **地址与族**：IPv4/IPv6 独立 fixture，同一 PDU 字节必须一致，仅外层 IP 头与偏移（54/74）不同；地址值域走 §3.7 地址模型四形态（PLMN / IPv4 / IPv6 / RFC 822 邮箱）。
- **多会话**：≥2 独立四元组（如发送方会话与 MMSC→接收方回放会话），Transaction-ID、Message-ID、事务状态互不串用；会话间包序按多会话展开（第二会话握手包号 = 前会话总包数 + 1）。
- **回放边界重申**：notification/delivery-ind 的 HTTP 承载是回放语义（§1 声明），不声称复刻 WAP Push 投递路径；不得因此把 WSP 端口/编码引入本版。
- 不得产生回绕长度或超量分配（multipart 累计长度恒等于 body 长度）。

## 9. 原子 ID 与完成定义

设计、testcase 与未来 `mmse.json` 必须使用同一组唯一语义 ID、同一顺序（原子用例：一个用例只验证一个协议行为——每类 PDU、每个值域组、每个编码原语形态、每条关联规则、每个错误分支各一；数量由协议结构决定，不设约 20 条基线）。共 **38 条：27 正例 + 11 负例**。

| # | ID | 类型 | 覆盖（设计 §） |
|---:|---|---|---|
| 1 | `mmse_send_req_ipv4` | 正 | §3.5/§4①：m-send-req 必选集 + multipart.related 完整体，POST/IPv4 单流基线（Sender-Visibility=Show 显式值例） |
| 2 | `mmse_send_conf_ok` | 正 | §3.5/§5：m-send-conf Ok、TID same_as、Message-ID 生成；HTTP 200 ≠ MMS 状态 |
| 3 | `mmse_send_conf_error` | 正 | §3.7/§4①：Response-Status 错误分支（Error-service-denied）+ Response-Text |
| 4 | `mmse_notification_ind` | 正 | §3.5/§4②：通知必选集 + From 可选头（PDU 总长 99B 逐字节复算，§3.5 工作例） |
| 5 | `mmse_retrieve_conf_immediate` | 正 | §3.5/§4②：立即取回（Figure 4）GET→200，TID 复用通知 |
| 6 | `mmse_notifyresp_deferred` | 正 | §3.5/§4③：通知确认 Deferred + Report-Allowed，TID same_as 通知 |
| 7 | `mmse_acknowledge_ind` | 正 | §3.5/§4③：延迟链尾确认，TID same_as 取回新事务（Figure 5 全链） |
| 8 | `mmse_delivery_ind_retrieved` | 正 | §3.5/§4④：递送报告必选集（无 TID），Message-ID same_as send-conf，Status=Retrieved |
| 9 | `mmse_delivery_ind_expired` | 正 | §3.7/§4④：Status=Expired 值域变体 |
| 10 | `mmse_read_rec_ind` | 正 | §3.5/§4⑤：读取报告（1.1 PDU）Read-Status=Read，Message-ID 关联 |
| 11 | `mmse_read_status_deleted` | 正 | §3.7：Read-Status=Deleted-without-being-read 变体 |
| 12 | `mmse_message_class_values` | 正 | §3.7：Message-Class 四值域（Personal/Advertisement/Informational/Auto） |
| 13 | `mmse_encoding_text_string` | 正 | §3.3/§3.4：Encoded-string-value 两形态（裸 Text-string 与 VL+charset106+UTF-8） |
| 14 | `mmse_text_string_quote` | 正 | §3.3：Text-string Quote 形态（首字符为分隔符时前置 0x7F） |
| 15 | `mmse_encoding_long_integer` | 正 | §3.3：Long-integer 大端（Date 4B / Message-Size 3B，定宽补零策略） |
| 16 | `mmse_encoding_value_length_uintvar` | 正 | §3.3：Value-length>30（0x1F+Uintvar）与 Uintvar part 长度 |
| 17 | `mmse_time_absolute_form` | 正 | §3.3/§3.4：Expiry/Delivery-Time 绝对 token（0x80+Date-value）形态 |
| 18 | `mmse_send_req_optional_headers` | 正 | §3.4：可选头全集（Cc/Bcc 多收件人、Sender-Visibility=Hide、Priority=High、Delivery-Time 出现） |
| 19 | `mmse_from_insert_token` | 正 | §3.4/§3.5：From insert-address-token 形态（1B 值体） |
| 20 | `mmse_addressing_types` | 正 | §3.7：地址模型四形态（/TYPE=PLMN、/TYPE=IPv4、/TYPE=IPv6、RFC822 邮箱，多 To 实例） |
| 21 | `mmse_multipart_related_root` | 正 | §3.6：multipart/related 父层 start/type 参数与 SMIL 根部件（RFC 2387） |
| 22 | `mmse_multipart_part_headers` | 正 | §3.6：part 头编码（charset/name 参数、Content-ID/Content-Location、text 子解析） |
| 23 | `mmse_multipart_media_part` | 正 | §3.6：媒体 part（image/jpeg well-known 码、magic bytes、无 charset） |
| 24 | `mmse_http_keepalive_multi_transaction` | 正 | §5/§4⑥：同连接多事务（提交+取回+确认）严格配对、Content-Length 自洽 |
| 25 | `mmse_ipv6` | 正 | §2/§8：IPv6 单流（ipv6.nxt=6、offset 74、PDU 字节同 v4） |
| 26 | `mmse_multi_session` | 正 | §5/§4⑦：多会话展开双四元组（发送链+接收回放链），TID/MsgID 不串用 |
| 27 | `mmse_mss_large_multipart` | 正 | §8/§3.6：大 multipart 跨 MSS ≥3 段重组后完整 |
| 28 | `mmse_neg_carrier_config` | 负 | §7：配置错（层链/Content-Type/端口） |
| 29 | `mmse_neg_pdu_head_order` | 负 | §7：首三头顺序违反 |
| 30 | `mmse_neg_unknown_pdu_type` | 负 | §7：Message-Type 未分配值或本版不产生值（0x88–0x93） |
| 31 | `mmse_neg_missing_content_type` | 负 | §7：有体 PDU 缺 Content-Type / 无体 PDU 带体 |
| 32 | `mmse_neg_multipart_structure` | 负 | §7：multipart 结构错（长度越界、start 无引用、part 数不符） |
| 33 | `mmse_neg_mandatory_missing` | 负 | §7：必选字段缺失 |
| 34 | `mmse_neg_tid_correlation` | 负 | §7：Transaction-ID 关联错配 |
| 35 | `mmse_neg_msgid_correlation` | 负 | §7：Message-ID 无来源（跨事务回指断裂） |
| 36 | `mmse_neg_sequence` | 负 | §7：事务顺序错（ack 先于 retrieve 等） |
| 37 | `mmse_neg_length` | 负 | §7：长度错（Content-Length/Long-integer/Uintvar/Value-length/TID 上界） |
| 38 | `mmse_neg_value_range` | 负 | §7：枚举值域外取值、不产生形态/字段族归口拒绝 |

完成定义：注册 `tcp→http→mmse` 层链；逐字段生成并验证 §3 的 PDU 编码（首三头顺序、Content-Type 收尾、值域）、multipart/SMIL/附件、§5 事务关联与状态机、§7 错误传播；38 个语义 ID 正负断言完成；未注册阶段只接受 `unknown layer` 占位。

## 10. 修订记录

- v1.0.0（2026-08-21）：旧稿首版（14 正 + 6 负：WAP/WSP/WTP 与 HTTP 双载体、含 pcap_nic/multi_flow/carrier_equivalence 等 ID）。
- v2.0.0（2026-09-01）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写，取代 2026-08-21 旧稿（旧稿见 git 历史）。**载体收敛为 HTTP/1.1 明文主 profile `mmse_http_v1`**（WAP/WSP/WTP/WAP Push 降为 §1 未注册边界，理由：现网 MM1 走 HTTP POST + application/vnd.wap.mms-message，WAP-209 §7 PDU 字节与承载无关）；**规范编号更正**（WAP-230 是 WSP 编号；MMS 封装 = WAP-209 + OMA-MMS-ENC，档案索引核实无 WAP-230-MMS-ENC 文档）；用例按 v1.1 原子原则从 20 条重排为 36 条（25 正 + 11 负）——8 类 PDU 各一例、Response-Status/Status/Read-Status/Message-Class 值域分例、编码原语（Text-string 两形态/Long-integer/Value-length+Uintvar/绝对时间）分例、multipart 三例（父层/part 头/媒体 part）、多事务 keep-alive、IPv6、多会话、MSS 大消息；新增 §4 业务场景分析（WAP-206 Figure 3/4/5 事务流对照）、§5 事务关联取材规则逐对列出、§6 JSON 配置 typedef；以本机 tshark 3.6.14 构造 pcap 实证（8 类 PDU + v6 + 全值域字段解码通过：`mmse.message_type/transaction_id/mms_version/from/to/cc/bcc/subject/message_class.id/expiry.rel/priority/delivery_report/read_report/response_status/response_text/status/read_status/message_id/message_size/content_location/date` 与 `wsp.header.content_type/content_id/content_location`、`wsp.parameter.name/start/charset`、`wsp.multipart` 均实测可见）并固化为断言基线；实测确认 Content-Type application/vnd.wap.mms-message 触发 tshark 自动内层解码（请求体与响应体均触发）。状态：**待独立隔离审查**。
- v2.0.1（2026-09-01）：按独立隔离审查 10 项问题清单逐项修复（2 MAJOR / 8 MINOR），关键项：
  - **M01**：用例 4 `http.content_length=88` 与自身断言矛盾 → §3.5 增加"字段宽度速查 + L_min 公式 + 工作例（通知事件 PDU 逐字节复算 = 99B）"、§6 fixture 钉死 → 用例 4 同步改为 `99`；§3.5 公式从"只含必选头未声明范围"改为速查+累加（**M04 同步关闭**）。
  - **M02**：Text-string Quote 与 From insert-token 各缺正例、其余形态声明未产生 → §9 新增 `mmse_text_string_quote`（#14）、`mmse_from_insert_token`（#19）两条正例；空串 / Application-header / charset 高值在 §1 显式"本版不产生"并归口 `mmse_neg_value_range`（负例故障输入列已扩列，锚词不变）。
  - **M03**：TID 在 retrieve-conf 出现性冲突（§3.4 行 vs §3.5 条目） → 统一为**必选**，出处 WAP-209 §7.3 表 5（§3.4 表行与 §3.5 retrieve-conf 条目同步标注；§3.5 公式补入 TID 项）。
  - **M05**：覆盖声明超实际（Status 五值仅测三、Priority 仅 Normal、Sender-Visibility 仅 Hide、地址缺 IPv6 形态） → §4 收窄到实测集合（Status 三值 / Priority 两值）；个别补值：用例 1 增 Sender-Visibility=Show、用例 18 增 Priority=High、用例 20 地址扩为四形态（多 To 实例补邮箱、Bcc 改 /TYPE=IPv6）。
  - **M06**：版本互操作接收侧行为无用例 → §3.7 显式"接收侧反应性互操作不适用本版"，由 §4/§5/§7 协同声明。
  - **M07**：已分配但本版不产生 PDU（0x88–0x93）配置时无归口 → §1 §7 `mmse_neg_unknown_pdu_type`/`mmse_neg_value_range` 显式归口拒绝。
  - **M08**：用例 22/25（重排后 #24 `mmse_http_keepalive_multi_transaction` / #27 `mmse_mss_large_multipart`）"无 Connection: close / 严格交替 / tcp.len 分布"无可执行字段映射 → 判定字段钉死：`http.connection` 全帧无 close、按包位（4/6/8 请求、5/7/9 响应）判严格交替、逐段 `tcp.len` 数值与 Σ=消息总长。
  - **M09**：用例 14（重排后 #15）`8e 03 00 12 c0` 依赖未钉死策略 → §3.3 显式 Long-integer **定宽补零策略**（Date-value 恒 4B、Delta-seconds 与 Message-Size 恒 3B；注明与 WSP 最小编码的区别及选择理由）；§3.5 速查、§8 上界表同步。
  - **M10**：§3.6 "+1（partNum）"在 >127 parts 失效 → 改为 `+len(Uintvar(partNum))` + 本版部件数上界 ≤ 127（§8 上界表同步；>127 归口 `mmse_neg_length`）。
  - 索引顺序同步：设计 §9 27 正 + 11 负 = **38**（用例 §2 三方表 §8 一致）。
