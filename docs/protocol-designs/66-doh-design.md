# DOH（DNS over HTTPS / RFC 8484）设计契约

> 版本：v2.2.1（设计阶段）
> 日期：2026-08-31
> 状态：**v1.1 隔离审查已 clean**（v2.0.1）；现按《需求文档 v1.3》完成重审扩面修复（独立审查员 rr-doh：行为面约 135 点，2 CRITICAL + 7 MAJOR + MINOR 全项落地），配套用例 v3.0.0，**待复验**。记录见 §10。
> 配套文件：`docs/protocol-designs/66-doh-testcase.md`、`trafficgen/test/protocol_pcap/cases/doh.json`（当前 JSON 仅含注册前置占位，本版不写文件、不改代码；占位 dst_port 已与主 profile 对齐为 80）
> 规范基线：**RFC 8484**（DNS Queries over HTTPS，2018-10，按章节号引用）；**RFC 1035**（DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION，§3.1/§3.2/§4.1.1/§4.1.2 QNAME 与 wire 格式）；RFC 4648（base64url，§5）；RFC 7230（HTTP/1.1 消息语法与路由，§6.3 长连接/§6.3.2 禁 pipelining）；RFC 7231（HTTP/1.1 语义，§6.5.1 400/§6.5.4 404/§6.5.13 415）；RFC 9110（HTTP 语义，Cache-Control 缓存头）。
> 修订记录：v2.2.1（2026-09-01，rr-doh 二轮复验遗留小修）：N4 §6 wire_fault 枚举 22→26 值（清 carrier，并入 layer_chain/port_conflict；补 dns_id_range/ttl_range/qtype_token），§7 表头/表尾同步 26；D6 §5 事务定义残留引证 §6.3.1→§6.3.2；N5 非 2xx 响应头集合引证改「本版 fixture 决策，无 RFC 强制」；N6 §3.1「dns 为唯一查询参数」补 400 多参数正例除外条款；N9 配套用例计数改 110（v3.0.2）；N12 SVCB AliasForm fixture 形状钉死为 svc.example.net 真实目标名（根目标退化语义不采用）。v2.2.0（2026-09-01）：按《需求文档 v1.3》重审扩面（rr-doh 清单全落地）：新增 pcap/NIC 双输出契约声明、RST 不适用声明、端口变体覆盖声明、RCODE 值域全列（0/1/2/3/4/5/15 编排）、HTTPS/SVCB Answer RDATA 规格（RFC 9460）、SOA 负缓存规格（RFC 2308）、非 2xx 响应头集合钉死、GET Content-Type 泄漏规则、并发会话翻案纳入覆盖、大请求 MSS 不适用声明、65535 上界独立负例、RFC 7230 §6.3.1→§6.3.2 引证校正、§9 ID 权威改用例文档 §2；配套用例 38→110 条（v3.0.2，另行修订记录）。v2.0.1（2026-08-31）：按独立对抗审查 24 项清单修复（4C/5H/9M/6L），关键项：错误状态码出处改 RFC 7231+本版映射决策、§5.2 错引更正并如实声明明文偏差、负例表去重与 wire_fault 14 值对齐、401/415/406 retry 语义改正、packet_count 公式统一为 3+N+4（详见 §10）。v2.0.0（2026-08-31）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写/review，取代 2026-08-20 旧稿（旧稿见 git 历史）。

## 1. 范围、profile 和未注册边界

本版定义 RFC 8484 的 DNS over HTTPS（DOH）明文链路：**HTTP/1.1 明文载体**（TCP）之上的 DNS wire message 的 GET/POST 两种映射、`application/dns-message` 媒体类型、GET 的 base64url（RFC 4648 §5，无填充）查询参数编码、HTTP 头逐项规则、DNS wire message 的 12 字节头与 Question 编码（RFC 1035）、缓存头（RFC 8484 §5.1）、错误响应形态（RFC 8484 §4.2.1 非 2xx 不含 DNS 回复；具体状态码语义按 RFC 7231 + 本版映射决策，见 §3.1）、IPv4/IPv6、多会话与多事务。

| profile（协议档案） | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `doh_http1_plain`（主 profile） | TCP + HTTP/1.1 明文（调试端口默认 80） | POST/GET、`application/dns-message`、base64url、DNS wire 头/Question/Answer、缓存头、400/404/415 错误响应 | 真实 DNS 解析成功/失败、上游递归服务器语义、EDNS/DNSSEC 扩展记录语义正确性 |
| `doh_https_boundary` | TLS/TCP（端口 443） | 仅边界声明，不设语义用例 | 解密 TLS 后声称看见 HTTP 头或 DNS wire（本生成器无 key log） |
| `doh_http2_boundary` / `doh_http3_boundary` | HTTP/2（TLS）/ HTTP/3（QUIC） | 仅边界声明 | 明文 HTTP/2/3 或 QUIC stream 重组断言 |

**载体决策与理由**：本生成器 `http` 层默认产出 HTTP/1.1 明文链路（HTTP 语义、Content-Length、keep-alive 由 `http` 层承载，与 `hls`/`cwmp` 同款分层先例），因此 DOH 主线 profile 为 `doh_http1_plain`。**如实声明偏差**：RFC 8484 §5 要求 DoH 使用 https scheme（"MUST use the https URI scheme"），本生成器 `http` 层只产明文 HTTP/1.1，故主 profile `doh_http1_plain` 属**测试用途的规范外偏差**；媒体类型/DNS wire/URI 模板仍按 RFC 8484 §6/§4.1 执行；TLS/HTTP2/3 为边界。RFC 8484 §5.2 的原文（"Earlier versions of HTTP are capable of conveying the semantic requirements of this specification, but may result in very poor performance"）出自 §5.2 且语境是 TLS 内 HTTP/1.1 vs HTTP/2 的比较，**不构成对明文 HTTP/1.1 的规范允许**——不得再把该句当"明文可用"依据。HTTPS/TLS 与 HTTP/2/3 均为**未注册边界**：本版不实现、不声称、不许静默转换，明文 HTTP/2/3 不是 DoH 标准用法（RFC 8484 的 HTTP/2/3 均指在 TLS 上的加密链路），故无 TLS key log 时无法断言内部字段。

**输出契约（pcap/NIC 双输出）**：本协议全部用例同时兼容两种输出路径——`pcap` 文件输出（断言以 tshark 读 pcap 为准）与 `port_group`/NIC 网口输出（同一份用例契约驱动真实发包，断言由抓包侧使用相同 tshark 字段/原始字节校验）；两路径共用同一 cases JSON，不设仅单路径可用的断言（需求文档 v1.3 §8.2-7）。

**未注册边界**：当前仓库没有注册 `doh` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/doh.json` 只保留一个不计入语义 ID 的注册前置占位 `doh_neg_unregistered`（`expect_error=true`、`error_contains` 精确为 `unknown layer`）。占位的拒绝、0 包或空 PCAP 不得报告为 DOH 行为通过；注册后按本文 §9 与用例文档 §2 的同一顺序替换为语义用例。

**动态值不硬编码**：DNS ID、随机查询名 label、随机端口为运行期或配置值，断言用 `nonzero`、`same_as_packet`、`distinct_values` 与稳定 token 字节；QNAME 主体、QTYPE、QCLASS、TTL、RCODE、应答内容属预配置值，允许 fixture 显式给出。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[tcp, http, doh]`（引擎自动补 `ip`；需要显式地址族时写 `[ip, tcp, http, doh]` 或 IPv6 等价链）。HTTP 语义（请求行/头/Content-Length/keep-alive）由 `http` 层承载，`doh` 终结层在其上产出 DNS wire 与 URI/base64url 编码与事务序列。

端口与 profile 对应：

| profile | 默认端口 | 说明 |
|---|---:|---|
| `doh_http1_plain` | 80 | 明文调试链路；端口可由配置显式覆盖（如 8080），planner 不得静默改写 |
| `doh_https_boundary` | 443 | 仅边界声明；未解密时不得断言 HTTP/DNS 内容 |

**端口变体覆盖声明（v2.2）**：非默认端口（如 8080）为显式正例落点（`doh_port_nondefault`，POST 与 GET 各一）——profile 默认 80，端口由配置覆盖、planner 不得静默改写（上行表格注记），断言 `tcp.dst_port` + 全栈语义与默认端口基线一致。

**固定偏移**：无 VLAN（虚拟局域网）、无 IP options、无 TCP options 时，HTTP 起行起点为 IPv4 offset（偏移）54（Ethernet 14 + IPv4 20 + TCP 20）、IPv6 offset 74（14 + IPv6 40 + TCP 20）。**DNS wire 在 HTTP body 内，偏移不固定**——DNS 内容从 body 起始字节开始，而 body 起点 = 54/74 + 该 fixture 固定 HTTP 头集合的字节长（头集合由配置钉死，偏移可预算）；因此 DNS 断言以 `http.file_data`（body 内容）+ tshark 内层解码字段 + frames 的 body 起始偏移表达，不以固定帧偏移表达。HTTP 消息边界由 Content-Length 界定，**TCP 分段边界不是 HTTP/DNS 消息边界**（RFC 7230 §3.2/§3.3.2）。

## 3. 线格式编码（逐项标注出处）

### 3.1 HTTP 请求/响应（RFC 8484 §4.1、§4.2.2、§6；RFC 7230）

**POST 请求**（DNS wire 直接作为 HTTP body，§6 "MUST NOT be encoded and is used directly as the HTTP message body"）：

```text
POST /dns-query HTTP/1.1
Host: <dst_ip 或配置 host>
Content-Type: application/dns-message
Accept: application/dns-message
Content-Length: <len(dns_wire)>
Connection: keep-alive | close

<dns_wire_message>
```

**GET 请求**（DNS wire 编为 base64url 无填充后放入 `dns` 查询参数，§4.1 URI 模板 `/dns-query{?dns}`、§6 无 padding 硬性要求；请求不携带 body；GET 的 `Content-Length: 0` 为**本版固定形态**——RFC 7230 §3.3.2 对无 payload 的请求是 SHOULD NOT 发送 Content-Length（含 0 值），RFC 8484 §4.1/§6 不要求 GET 携带该头；此形态属**与 §3.3.2 SHOULD NOT 的显式偏差声明**（测试用途），不挂靠为规范要求）：

```text
GET /dns-query?dns=<base64url(dns_wire)> HTTP/1.1
Host: <dst_ip 或配置 host>
Accept: application/dns-message
Content-Length: 0
Connection: keep-alive | close

（无 body）
```

**响应**（§4.2.2 示例）：

```text
HTTP/1.1 200 OK
Content-Type: application/dns-message
Content-Length: <len(dns_wire)>
Cache-Control: max-age=<答案最小 TTL>

<dns_wire_message>
```

HTTP 头逐项规则：

| 头 | 出现位置 | 值 | 出处与规则 |
|---|---|---|---|
| 请求行 | GET/POST | `POST /dns-query HTTP/1.1` / `GET /dns-query?dns=<b64> HTTP/1.1` | §4.1 URI 模板；`dns` 为唯一查询参数（除外：`doh_http_error_400_extra_param` 显式携带多余查询参数触发 400——错误形态正例 fixture，非查询映射） |
| `Host` | 请求 | dst_ip 或显式配置（默认 dst_ip） | RFC 7230 §5.4；生成器 `http` 层缺省 |
| `Content-Type` | 请求（POST）/响应 | `application/dns-message` | §6 媒体类型注册；请求用 POST 时表示 body 媒体类型，响应总是携带；**GET 请求不得携带 Content-Type（无 body；RFC 7230 §3.3.2）**——会话级头覆盖不得跨事务泄漏到 GET 事务，混合 GET/POST 会话中 Content-Type 逐事务声明 |
| `Accept` | 请求 | `application/dns-message` | §4.1 客户端 SHOULD 携带；本版默认带 |
| `Content-Length` | 请求（POST）/响应 | body 字节数（十进制 ASCII） | RFC 7230 §3.3.2；POST 请求与响应均等于 DNS wire 字节数；GET 请求为 0（本版固定形态，对 §3.3.2 SHOULD NOT 的显式偏差声明，见 §3.1 GET 注，非 RFC 8484 规范要求） |
| `Connection` | 请求（每笔） | `keep-alive`（多事务每笔请求均带；末笔按 close/keep-alive 配置决定，默认 close）/ `close`（单事务即末笔） | RFC 7230 §6.3；**本版钉死策略（§5）**：多事务下逐请求均显式携带 `Connection: keep-alive`，仅末笔事务按配置决定由 keep-alive 改为 close |
| `Cache-Control` | 响应 | `max-age=<秒>` | §5.1（见 §3.6） |

错误响应形态：**非 2xx 响应不得包含对原查询的 DNS 回复**（RFC 8484 §4.2.1），自动应答产空 body、无 DNS wire（§5 确定性规则）。**非 2xx 响应头集合（本版钉死）**：状态行 + `Content-Length: 0`，**不携带** `Content-Type` 与 `Cache-Control`（无 body 无媒体类型、无内容可缓存；头集合为本版 fixture 决策，无 RFC 强制）——用例 18/19/20 的 `http.content_length=0` 断言与此处头集合配套；Content-Type/Cache-Control 存在性断言只在 2xx 用例。状态码语义出处：**400**（RFC 7231 §6.5.1 通用语义 + 本版映射决策：GET 缺 `dns` 参数时映射为 400）、**404**（RFC 7231 §6.5.4 通用语义 + 本版映射决策：URI 无对应查询路径）、**415**（RFC 7231 §6.5.13 通用语义 + 本版映射决策：请求媒体类型不支持）——RFC 8484 §4.2.1 原文不提 400/404（其状态码语境限于 401/406/415 的客户端重试建议，见 §5），故 400/404 的语义不挂靠 §4.2.1。非 2xx 状态经事件 `response.status`（或 `http` 子映射）声明（§6 配置通道）。**5xx/408/429 边界声明（H05）**：本版 fixture 只编排 400/404/415 三种错误形态（§4.2.1 所指语义面）；401/406 不产生（retry 语义声明，§5）；5xx/408/429 等其余状态码属通用 HTTP 语义，本版不编排、`response.status` 通道不禁止（实现期如需可声明），不计入 DOH 语义覆盖统计。

### 3.2 DNS wire header（RFC 1035 §4.1.1，12 字节，全大端）

| 字段 | 偏移 | 宽度 | 值域 | 本版默认 | 说明 |
|---|---|---|---:|---|---|
| ID（Transaction ID） | 0 | 2B | 0x0000–0xFFFF | 配置/随机 | 请求/响应关联标识，响应必须回带同值 |
| QR | 2 bit15 | 1bit | 0=查询,1=响应 | 0（请求）/1（响应） | Flags 高 bit |
| Opcode | 2 bit14–11 | 4bit | 0–15 | 0（QUERY） | 本版仅 0——**validator 决策**：声明 Opcode≠0 的配置拒绝（wire_fault `opcode_nonzero`，RFC 1035 §4.1.1 其余值属其它协议用途） |
| AA | 2 bit10 | 1bit | 0/1 | 0 | 响应侧可选 |
| TC | 2 bit9 | 1bit | 0/1 | 0 | 截断位，本版不置位 |
| RD | 2 bit8 | 1bit | 0/1 | 1（请求） | 期望递归 |
| RA | 2 bit7 | 1bit | 0/1 | 0（请求）/1（响应） | 递归可用 |
| Z | 2 bit6–4 | 3bit | 0 | 0 | 保留必为 0 |
| RCODE | 2 bit3–0 | 4bit | 0–15 | 按事件配置 | 响应码：0 NOERROR、1 FORMERR、2 SERVFAIL、3 NXDOMAIN、4 NOTIMP、5 REFUSED（RFC 1035 §4.1.1）；9 NOTAUTH/10 NOTZONE（RFC 2136/扩展段，实现期回对）；15 为 4bit 上界。fixture 编排覆盖 0/1/2/3/4/5/15 |
| QDCOUNT | 4 | 2B | 0–65535 | 1 | Question 数；本版请求/响应恒为 1 |
| ANCOUNT | 6 | 2B | 0–65535 | 按答案数 | Answer 数 |
| NSCOUNT | 8 | 2B | 0–65535 | 0 | Authority 数 |
| ARCOUNT | 10 | 2B | 0–65535 | 0 | Additional 数（本版不产生 EDNS OPT 记录；RFC 8484 §6 服务器必须忽略 EDNS UDP payload size，但本版 fixture 不构造 OPT） |

字节序：**全部多字节字段（ID、各 COUNT）网络字节序（大端）**，与 payload 内 QTYPE/QCLASS/TTL/RDLENGTH 一致，无混写。

**DNS ID=0 的 SHOULD 与有意偏离（M6 修复）**：RFC 8484 §4.1 建议 DoH 客户端将 DNS ID 置 0（SHOULD，原文 "SHOULD use a DNS ID of 0 in every DNS request"——HTTP 层已提供请求/响应关联，变化的 ID 会使语义等价的查询被 HTTP 缓存分开存储，不利缓存命中）；本版默认允许配置/随机 ID 以便断言 16-bit 关联与 ID 边界（正例 10/23），属对该 SHOULD 的**有意偏离**，非规范违反（偏离 SHOULD 不等于不合规，在此显式声明，testcase 用例 23 对应标注）。**逐字段覆盖声明（M1 修复）**：本表 13 个字段（ID 1 + flags 7 个 bit 域 + RCODE + 4 个 COUNT）全部进入 `doh_dns_header_query` 断言清单，AA/TC/Z/NSCOUNT/ARCOUNT 显式断言（按 tshark 3.6.14 实测发射帧分布：请求帧发射 QR/Opcode/TC/RD/Z 与 4 个 COUNT；TC/Z 在响应帧同样发射、断言双侧；AA/RA/RCODE 仅响应帧发射）。

### 3.3 Question 编码（RFC 1035 §4.1.2）

```
QNAME  <长度前缀标签序列>       变长，以零字节根标签终止
QTYPE  2B 大端                查询类型
QCLASS 2B 大端                查询类
```

QNAME 编码规则（RFC 1035 §3.1 编码推导；限值清单 §2.3.4）：域名被编码为 label 序列，每个 label 前导 1 字节长度前缀（0–63），**以 1 字节 0x00 根标签终止**；全名（含所有长度前缀与根标签）最长 255 字节；单标签最长 63 字节；不压缩（本版 query/response 均不用压缩指针，offset 指向 name 域本身的压缩在本版不产生）。

QTYPE/QCLASS 值（§3.2.2/§3.2.3）：QTYPE 1=A、28=AAAA、65=HTTPS（SVCB/HTTPS 类型，RFC 9460）、15=MX、16=TXT 等；QCLASS 1=IN。**未知/自定义值决策（v2.2）**：QTYPE/QCLASS 为 16-bit 数值，任意数值合法透传（RFC 1035 值域）；**非数字 token**（如 `qtype: "BOGUS"`）由 validator 拒绝（wire_fault `qtype_token`，锚 `qtype`/`value`）。本版 fixture 覆盖 A/AAAA/HTTPS/MX/TXT + QCLASS IN/CHAOS(3)。

Answer 编码（§4.1.3，响应侧）：`NAME`（本版为完整 QNAME 或压缩指针——压缩指针仅响应侧允许，本版响应回带完整 QNAME）+ `TYPE` 2B + `CLASS` 2B + `TTL` 4B + `RDLENGTH` 2B + `RDATA` 变长。A 记录 RDATA=4B 大端 IPv4；AAAA 记录 RDATA=16B IPv6；TTL 为 32 位无符号秒（0x00000000–0xFFFFFFFF）。**HTTPS/SVCB Answer RDATA（RFC 9460 §2.2，本版 fixture 形状）**：`SvcPriority` 2B 大端 + `TargetName`（QNAME 同款 label 编码，根名 `0x00` 合法）+ `SvcParams`（若干 `SvcParamKey` 2B 大端 + `SvcParamLength` 2B 大端 + Value 变长；无参数时为空）。fixture 覆盖两形态：优先级+根名+alpn 参数（key=1，`h2`）；AliasForm=优先级 0+真实目标名 `svc.example.net`+空参数（RDLENGTH 19，与用例 #41 一致；根目标退化语义 fixture 不采用）。CNAME Answer RDATA = QNAME 同款 label 编码（§3.1）；MX = 偏好 2B 大端 + 交换名 label 编码（§3.3.9）；TXT = 字符串序列（每段前导 1B 长度 0–255，§3.3.14）；SOA = MNAME/RNAME label 编码 + 5×4B 大端（Serial/Refresh/Retry/Expire/MINIMUM，§3.3.7，负缓存用）。

### 3.4 base64url 编码（RFC 4648 §5 / RFC 8484 §6）

GET 的 `dns` 查询参数值 = DNS wire message 的 base64url 编码：字母表 `A-Z a-z 0-9 - _`（`-`/`_` 替代标准 base64 的 `+`/`/`），**去除 `=` padding（§6 MUST NOT be included）**；未填充长度公式 `len_b64 = ceil(len_wire * 4 / 3)`。解码侧必须逐字节验证：出现**标准 base64 字母表字符（`+`/`/`）、padding `=`**、或任何非 base64url 字母表字符、或解码后字节数 <12（不足 DNS 头）均属错误（进负例，§7）。**两条截断路径显式区分（L2 修复）**：`b64_short`（base64 解码**产出** <12B，故障在解码链）与 `dns_header_short`（POST body **原始**字节 <12B，不经 base64 解码链）是两条不同的校验路径，实现不得合并成一条。

### 3.5 每消息长度公式

- DNS wire 请求：`L = 12 + QNAME_len + 4`，其中 `QNAME_len = len(name) + 2`（`len(name)` 为点分展示长度；推导：标签字符数 = len − (标签数−1)，加每标签 1B 长度前缀（标签数）+ 根标签 1B → len − n + 1 + n + 1 = len + 2，与标签数无关）。例：`www.example.com`（展示长度 15）→ QNAME_len = 17 → L = 12+17+4 = **33**（tshark 实测 http.content_length=33 印证）。
- DNS wire 响应：`L = 12 + QNAME_len + 4 + Σ_answer (QNAME_len + 10 + RDLENGTH)`（无压缩时；NAME/TYPE/CLASS/TTL/RDLENGTH = QNAME_len + 2+2+4+2）。例：上例 + 一条 A 答案（RDLENGTH=4）→ L = 12+17+4 + (17+10+4) = **64**（tshark 实测 http.content_length=64 印证）。
- POST 请求 `Content-Length = L`；GET 查询参数长度 = `ceil(L*4/3)`（**不替代 Content-Length，GET 请求无 body**）；响应 `Content-Length = L_response`。
- 帧长上界：`frame_len ≤ 14(eth) + 20/40(IP) + 20(TCP) + HTTP 头长 + Content-Length`；跨 MSS 分段规则见 §8。

### 3.6 缓存头（RFC 8484 §5.1）

服务器 SHOULD 给响应显式 HTTP 新鲜度生命周期，且**必须 ≤ 答案区最小 TTL，等于为 RECOMMENDED**；负响应（Answer 空且 Authority 含 SOA）新鲜度不得大于 SOA MINIMUM（RFC 2308 §5 负缓存语义；SOA MINIMUM = SOA RDATA 末 4B）；客户端必须考虑 `Age` 头（TTL − Age）。**负缓存 fixture 形状**：ANCOUNT=0 + NSCOUNT=1 + Authority 含一条 SOA 记录（RDATA 形状见 §3.3），`Cache-Control: max-age` = SOA MINIMUM 值。本版 fixture：`Cache-Control: max-age=<配置的 ttl_sec>`，默认等于答案最小 TTL；TTL=0 时 `max-age=0`；TTL=0xFFFFFFFF 时 `max-age=4294967295`（见 §8 边界）。POST 响应按 §5.1 默认不可缓存，本版响应恒为显式 `max-age`，不模拟缓存缺失形态。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性声明**：本引擎对 DOH 采用**声明式脚本化回放**——配置是剧本（sessions[]/events[] 逐条声明），引擎是回放者，按序产出帧；"事件驱动"一词不用于定性整体行为，仅用于两处反应性成分：①自动应答（收到请求帧自动补 DNS 响应帧）；②连接边界（事件序列中源端口切换触发新 TCP 连接）。

| 现网场景 | 事务交互 | 驱动顺序 | 对应用例 |
|---|---|---|---|
| ① 解析器查询 A/AAAA（最常见：浏览器/系统解析器向 DoH 服务器查记录） | TCP→POST 或 GET→200+Cache-Control→（keep-alive 下一笔）→FIN；**响应侧归属：自动应答（2xx + DNS wire，ID 回带）** | 客户端驱动全程 | `doh_post_ipv4_http11`、`doh_get_ipv4_base64url`、`doh_dns_question_a`、`doh_dns_question_aaaa` |
| ② HTTPS/SVCB 记录查询（浏览器连接前查询 HTTPS 记录，RFC 9460 场景） | 同①，QTYPE=65；**响应侧归属：自动应答（HTTPS 记录 Answer）** | 客户端驱动 | `doh_dns_question_https` |
| ③ 递归解析失败/NXDOMAIN（§4.2.1：HTTP 2xx 携带任意 DNS RCODE） | 请求→HTTP 200 + RCODE 3/2；**响应侧归属：自动应答（200 + ANCOUNT=0）** | 客户端驱动 | `doh_dns_response_nxdomain`、`doh_dns_response_servfail` |
| ④ 缓存策略（§5.1：max-age 绑定答案最小 TTL） | 响应携带 Cache-Control；**响应侧归属：自动应答（max-age=答案最小 TTL）** | 客户端驱动 | `doh_http_cache_control`、`doh_dns_ttl_boundary` |
| ⑤ DoH 多查询长连接（客户端同连接连续多笔查询，HTTP/1.1 keep-alive 多事务，RFC 7230 §6.3；**响应侧归属：自动应答逐笔补 2xx + DNS wire**） | 同连接多笔请求/响应严格交替 | 客户端驱动，事件编排 | `doh_http_keepalive_multi_transaction` |
| ⑥ POST 变体（私有/长查询，body 直传） | POST+Content-Length；**响应侧归属：自动应答（2xx，Content-Length=L_response）** | 客户端驱动 | `doh_http_content_length_exact` |
| ⑦ 错误响应（缺 dns 参数/未知路径/媒体类型不支持） | GET→400 / GET→404 / POST→415，空 body；**响应侧归属：自动应答（非 2xx 通道，空 body 无 DNS wire）** | 客户端驱动 | `doh_http_error_400/404/415` |

**26 个负例按六类错误打标（L5 修复 + v2.2 扩面）**——与 §7 表、用例文档 §5 逐一对齐，每类 ≥1：
- **配置类（3）**：`doh_neg_query_missing`（GET 缺 `dns` 参数）、`doh_neg_layer_chain_missing_http`（层链缺 http）、`doh_neg_port_conflict`（端口/载体矛盾）；
- **线格式类（7）**：`doh_neg_base64_invalid`、`doh_neg_base64_padding`、`doh_neg_base64_truncated`、`doh_neg_dns_header_short`、`doh_neg_dns_qdcount_zero`、`doh_neg_dns_qname_overflow`、`doh_neg_dns_question_truncated`（base64url 解码与 DNS wire 编码）；
- **状态机/HTTP 语义类（3）**：`doh_neg_content_type`（媒体类型非法）、`doh_neg_method`（方法不在 GET/POST 域）、`doh_neg_get_content_type`（GET 事务携带 Content-Type，无 body 载体禁/会话级头泄漏禁）；
- **关联类（3）**：`doh_neg_response_id`（ID 错）、`doh_neg_response_question`（Question 错配/2xx 无 DNS 体合并分支）、`doh_neg_response_qr`（响应声明 QR=0）；
- **长度/计数类（7）**：`doh_neg_content_length`（Content-Length≠body 字节，含 POST 无 body 合并分支）、`doh_neg_wire_over_max`（声明 wire >65535）、`doh_neg_rdlength_mismatch`（RDLENGTH≠RDATA 实长）、`doh_neg_ancount_mismatch`（ANCOUNT≠答案数）、`doh_neg_qdcount_multi`（QDCOUNT>1，本版恒 1）、`doh_neg_dns_id_range`（dns_id 65536 越界）、`doh_neg_ttl_range`（TTL 2^32 越界）；
- **值域类（3）**：`doh_neg_opcode_nonzero`（Opcode≠0，本版仅 QUERY）、`doh_neg_z_nonzero`（Z 保留位非 0）、`doh_neg_qtype_token`（qtype/qclass 非数字 token）；

**五层覆盖逐层结论**：功能层——GET/POST 两映射、DNS 头 12B 逐字段、Question 各查询类型、Answer 结构、RCODE 值域、缓存头、错误状态响应全正例；每类错误分支负例（§7）。性能层——大响应跨 MSS 分段重组（`doh_mss_large_response`）、QNAME 255/63 上界、DNS 头计数上界；**大请求跨 MSS 显式不适用**：请求侧 DNS wire 受 RFC 上界约束（QNAME≤255 → wire ≤ ~275B），无跨段形态；性能大报文只在响应侧（多 Answer/长 TXT）。数据场景层——DNS ID 0/满值、TTL 0/满值、QCLASS/QTYPE 值、base64url 编码变体、非法值拒绝。地址与流层——IPv4/IPv6 独立 fixture、单流基线、多会话双四元组（`doh_multi_session`）；**流关联（控制流派生数据流）显式不适用**：DoH 是纯请求/响应查询协议，无控制流派生媒体/数据流，RFC 8484 全文无流关联概念；**多流（会话内部并发 HTTP/2 stream）显式不适用**：本版仅 HTTP/1.1 明文，HTTP/1.1 一个连接内请求/响应严格配对（RFC 7230 §6.3/§6.3.2），无 stream 概念（§1 边界声明）。**RST/异常中断显式不适用**：生成器会话终止统一走 FIN 挥手（§5 Terminating/Closed），RST 属传输层异常注入面、非 DOH 语义；传输层异常由框架通用用例承载。业务层——解析器查询、HTTPS 记录、缓存策略、长连接多查询、POST 变体、IPv6 均为现网日常，优先于教科书全类型遍历。

## 5. 消息/事务模型与状态机

**事务定义**：DOH 事务 = 同一 HTTP 连接内一次完整的 HTTP 请求/响应对（RFC 8484 §4.1 的 query/response 交互）。**DNS 事务关联 = DNS ID**：响应必须回带与请求相同的 16-bit ID（RFC 1035 §4.1.1）——DNS ID 在 HTTP 层映射（body 内或 URI query 解码后），与 HTTP/1.1 请求/响应配对（RFC 7230 §6.3.2，本版顺序执行、无 pipelining）共同构成事务关联。**多事务** = 一个 TCP 连接内多笔查询按序执行（keep-alive），每笔独立 DNS ID、独立 QNAME，请求/响应严格交替。**事务交互**示例：同一连接先查 A 再查 AAAA（互不依赖，但依赖同一连接状态）；缓存头 max-age 影响客户端后续是否重查（本版不模拟客户端缓存决策，只产出响应头）。

**逐请求 Connection 策略（钉死，H2 修复）**：多事务连接内**每笔 HTTP 请求均携带 `Connection: keep-alive`**（RFC 7230 §6.3 长连接语义），仅**末笔事务按 close/keep-alive 配置决定**（默认 `close`）——本策略为生成器产线依据（§3.1 头表、testcase 用例 15 按此断言），废弃"只有首请求带 keep-alive"的无依据表述。

**DNS ID=0 的 SHOULD 与有意偏离（M6 修复）**：RFC 8484 §4.1 建议 DoH 客户端将 DNS ID 置 0（SHOULD，原文 "SHOULD use a DNS ID of 0 in every DNS request"，缓存友好——HTTP 层已提供事务关联，变化的 ID 会使语义等价的查询被分开缓存）；本版允许配置/随机 ID 以便断言请求/响应关联与 ID 边界（正例 10/23），属对该 SHOULD 的**有意偏离**（偏离 SHOULD 不构成不合规，但在此显式声明）。

会话状态机（HTTP/1.1 明文，TCP 层）：

| 状态 | 允许事件 | 必须保持 |
|---|---|---|
| `ConnectPending` | TCP 三次握手完成 | 握手后首帧是 HTTP 请求（GET 或 POST） |
| `RequestSent` | 发送 HTTP 请求（含 DNS wire） | POST：Content-Length=body 字节数；GET：`dns` 参数无 padding base64url、无 body |
| `ResponsePending` | 收到 HTTP 响应 | 响应 Content-Type=application/dns-message（2xx 时）；响应 DNS ID=请求 ID；2xx 必须携带 DNS body，非 2xx 不得携带（§4.2.1）；**非 2xx 时自动应答产空 body、无 DNS wire**（§5 确定性规则） |
| `KeepAlive`（多事务） | 下一笔请求（DNS ID 递增/独立） | 请求/响应严格交替，不得 pipelining（RFC 7230 §6.3.2 本版顺序执行）；**逐请求 Connection 策略钉死**：每笔请求均显式携带 `Connection: keep-alive`，仅末笔事务按 close/keep-alive 配置决定（默认 close），保证请求/响应严格配对不靠隐式推断 |
| `Terminating` | FIN 挥手 | 全部事务完成后才挥手；失败连接同样统一 FIN 挥手终止（**RST 不产生**，§4 RST 不适用声明——状态机确定性要求写死，不留 TCP 语义自由度） |
| `Closed` | TCP FIN | 关闭后不得产生新业务帧 |

**错误与 retry 语义**：HTTP 非 2xx（400/404/415）是**合法错误响应**（正例形态，RFC 8484 §4.2.1：非 2xx 响应不含对原查询的 DNS 回复）；DNS RCODE 非 0（NXDOMAIN/SERVFAIL）是**合法 DNS 响应**（正例，RFC 8484 §4.2.1 "a successful HTTP response with a 2xx status code is used for any valid DNS response, regardless of the DNS response code"）。客户端 retry 语义按 RFC 8484 §4.2.1 原文（H4 修复）：**401（授权失败类）建议对同一 DoH 服务器重试**；**415（媒体类型不支持）与 406（无法生成客户端可接受的表示）建议换不同 DoH 服务器重试**——本版生成器不模拟客户端 retry（未实现该算法，RFC 8484 亦未定义完整重试算法），401/406 本版不产生，415 响应属正例错误形态（仅断言响应形态）。配置、线格式、长度或关联错误进入负例（§7），与合法错误响应严格区分。

**自动派生规则**（引擎自动补出的帧，逐条列出触发条件与内容）：
- `http` 层自动补 HTTP/1.1 请求行与头（方法/URI/Host/Content-Type/Accept/Content-Length/Connection）与响应行/头（状态行/Content-Type/Content-Length/Cache-Control）；头可由 doh 事件 `http` 子映射覆盖。
- `doh` 层自动补 DNS wire：请求 = 12B 头 + Question；响应 = 自动应答（收到请求帧后自动补）——QR=1、ID 回带请求 ID、RA=1、QDCOUNT=1（回带请求 Question）、ANCOUNT/答案/RCODE 按事件配置。**非 2xx 确定性规则（H1 修复）**：事件声明非 2xx 状态（`response.status`，见 §6 状态码通道）时，自动应答**只产 HTTP 状态行/头 + 空 body，不产 DNS wire**（§4.2.1 非 2xx 不含 DNS 回复）；未声明状态时默认 2xx 并携带 DNS body。
- 连接边界：事件序列中源端口变化触发新 TCP 连接（多会话展开），第二会话包号起点 = 前会话总包数 + 1。

## 6. 配置 typedef（JSON 形状示例，非 Go 代码）

```json
{
  "layers": [{"tcp": {}}, {"http": {}}, {"doh": {}}],
  "src_ip": "192.0.2.66", "dst_ip": "198.51.100.66",
  "src_port": 42066, "dst_port": 80,
  "doh": {
    "profile": "doh_http1_plain",
    "method": "POST",
    "uri": "/dns-query",
    "sessions": [
      {
        "src_port": 42066, "dst_port": 80,
        "events": [
          {
            "kind": "query",
            "dns_id": {"strategy": "rand", "range": [1, 65535], "seed": 6601},
            "name": "www.example.com", "qtype": "A", "qclass": "IN",
            "response": {
              "status": 200,
              "rcode": "NOERROR",
              "answers": [
                {"name": "www.example.com", "type": "A", "ttl": 300, "rdata": "192.0.2.1"}
              ]
            },
            "http": {
              "request_headers": {"Accept": "application/dns-message"},
              "response_headers": {"Cache-Control": "max-age=300"}
            }
          },
          { "kind": "query",
            "dns_id": {"strategy": "inc", "range": [1, 65535], "step": 1},
            "name": "www.example.com", "qtype": "AAAA", "qclass": "IN",
            "response": { "rcode": "NOERROR",
              "answers": [{"name": "www.example.com", "type": "AAAA", "ttl": 300, "rdata": "2001:db8::1"}] } }
        ]
      },
      { "src_port": 42067, "dst_port": 80,
        "events": [
          { "kind": "query", "dns_id": {"strategy": "fixed", "value": 1},
            "name": "www.example.net", "qtype": "HTTPS", "qclass": "IN",
            "response": { "rcode": "NXDOMAIN", "answers": [] } }
        ] }
    ],
    "wire_fault": ""
  }
}
```

形状要点：`sessions[]` = 统一术语的**事件编排会话**（每个自带四元组与事件序列，多会话展开按序整块回放，第二会话包号起点 = 前会话总包数 + 1）；`events[]` = 会话的**事件序列**，元素为一笔 DNS 查询事务（`kind: query`）；`method`/`uri` 为会话级 HTTP 骨架默认值，可被事件 `http` 子映射覆盖（HTTP 头覆盖是显式写全的通道）；**`response.status` 为非 2xx 状态码声明通道（H1 修复）**——缺省 200；声明 400/404/415 等非 2xx 时自动应答只产状态行/头 + 空 body、无 DNS wire（§3.1/§5 确定性规则，正例 18/19/20 由此配置，也可复用 `http` 子映射 `response_status_code` 等价表达）；`dns_id` 支持 fixed/inc/rand 策略，边界用例显式固定 0/65535；`response` 声明自动应答内容（rcode/answers），answers 为空时响应仅含头+Question（NXDOMAIN/SERVFAIL 形态）；**逐请求 Connection 策略**：多事务每笔请求默认 `Connection: keep-alive`，末笔按 close/keep-alive 配置决定（默认 close，§5 钉死）。`wire_fault` 仅负例注入口，**取值 26 个、与 §7 表/用例文档 §5 的 26 个负例一一对应（v2.2 扩面 + v2.2.1 复验同步）**：`query_missing`/`base64`/`padding`/`b64_short`/`dns_header_short`/`qdcount`/`qname`/`question_truncated`/`content_type`/`method`/`content_length`/`layer_chain`/`port_conflict`/`response_id`/`response_question`/`wire_over_max`/`opcode_nonzero`/`get_content_type`/`response_qr`/`z_nonzero`/`rdlength_mismatch`/`ancount_mismatch`/`qdcount_multi`/`dns_id_range`/`ttl_range`/`qtype_token`（v2.0.1 原 14 值中 `carrier` 由载体/端口校验取代、并入 layer_chain/port_conflict 两值；v2.2 扩 8 值：wire 65535 上界、Opcode≠0、GET Content-Type 泄漏、响应 QR=0、Z 非 0、RDLENGTH 失配、ANCOUNT 失配、QDCOUNT>1；v2.2.1 再扩 layer_chain/port_conflict/dns_id_range/ttl_range/qtype_token——层次链缺 http、端口载体矛盾、DNS ID 65536 越界、TTL 2^32 越界、QTYPE 非数字 token），不得成为线上字段。`qclass` 默认 IN。**驱动顺序**：events[] 按序逐笔回放，自动应答随事件即时补响应；多会话整块展开。并发会话（`concurrent: true`）纳入覆盖（v2.2 翻案，与 64-cwmp 同判例）：HTTP/1.1「单连接串行」约束的是单个会话内部的事务交替，不约束生成器级多设备并发——`doh_concurrent_sessions` 用双客户端四元组交错回放（`concurrent: true`），断言 DNS ID/QNAME/事务状态互不串用。

## 7. 错误处理（负例锚词表）

以下输入必须由 planner/validator 拒绝并传播为 task error（任务错误），不得产出成功 PCAP、`completed/0 packet` 或仅 TCP/HTTP 外壳的假成功。锚词（anchor word）为 `error_contains` 断言字面值，与用例文档 §5 一一对应；**收敛规则（v1.3 §8.2-6）**：每行主锚词为实现钉死值——注册 `doh` 层时 validator 错误字面值必须包含该主锚词（备选词仅供实现期调整），注册后四件套同步、不再多选：

| 负例 ID | `wire_fault` 注入口（v2.2.1，26 值） | 故障输入（方向） | `error_contains` 主锚词（备选） | 依据 |
|---|---|---|---|---|
| `doh_neg_query_missing` | `query_missing` | GET 配置缺 `dns` 参数（URI 无 query） | `dns`（备选 query/parameter） | RFC 8484 §4.1+设计§7 |
| `doh_neg_base64_invalid` | `base64` | base64url 含非法字符（`+`/`/`/非字母表字节） | `base64`（备选 url/decode） | RFC 4648 §5+设计§7 |
| `doh_neg_base64_padding` | `padding` | base64url 带 `=` padding | `base64`（备选 padding/url） | RFC 8484 §6+设计§7 |
| `doh_neg_base64_truncated` | `b64_short` | base64url 解码产出 <12B（解码链） | `decode`（备选 truncate/length） | 设计§3.4/§7 |
| `doh_neg_dns_header_short` | `dns_header_short` | POST body 原始 <12B（不经解码链） | `dns`（备选 header/length） | RFC 1035 §4.1.1+设计§7 |
| `doh_neg_dns_qdcount_zero` | `qdcount` | QDCOUNT=0（本版 validator 决策） | `question`（备选 qdcount/dns） | 设计§7 决策 |
| `doh_neg_dns_qname_overflow` | `qname` | QNAME>255 或单标签>63 | `qname`（备选 label/length） | RFC 1035 §3.1+设计§7 |
| `doh_neg_dns_question_truncated` | `question_truncated` | Question 缺零标签终止/QTYPE/QCLASS 截断 | `question`（备选 wire/length） | RFC 1035 §4.1.2+设计§7 |
| `doh_neg_content_type` | `content_type` | Content-Type 非 application/dns-message | `content-type`（备选 media/type） | RFC 8484 §6+设计§7 |
| `doh_neg_method` | `method` | 方法非 POST/GET | `method`（备选 http） | RFC 8484 §4.1+设计§7 |
| `doh_neg_content_length` | `content_length` | POST Content-Length≠wire 字节/无 body | `content-length`（备选 length/body/dns） | RFC 7230 §3.3.2+设计§7 |
| `doh_neg_layer_chain_missing_http` | `layer_chain` | 层链缺 http（tcp→doh 直连） | `carrier`（备选 layer） | 设计§2/§7 |
| `doh_neg_port_conflict` | `port_conflict` | 端口/载体声明矛盾（明文 profile 配 443 等） | `port`（备选 carrier） | 设计§2/§7 |
| `doh_neg_response_id` | `response_id` | 响应 DNS ID≠请求 ID | `id`（备选 match/correlation） | RFC 1035 §4.1.1+设计§7 |
| `doh_neg_response_question` | `response_question` | 响应 Question 错配/2xx 无 DNS 体 | `question`（备选 match/body/wire） | RFC 8484 §4.2.1+设计§7 |
| `doh_neg_wire_over_max` | `wire_over_max` | 声明 DNS wire 总长 >65535 | `length`（备选 max/wire） | RFC 8484 §6+设计§8 |
| `doh_neg_opcode_nonzero` | `opcode_nonzero` | Opcode≠0（本版仅 QUERY） | `opcode`（备选 value） | RFC 1035 §4.1.1+设计§3.2 |
| `doh_neg_get_content_type` | `get_content_type` | GET 事务声明 Content-Type 头（无 body 载体禁） | `content-type`（备选 get/header） | RFC 7230 §3.3.2+设计§3.1 |
| `doh_neg_response_qr` | `response_qr` | 响应事件声明 QR=0（响应必须 QR=1） | `response`（备选 qr/flag） | RFC 1035 §4.1.1+设计§5 |
| `doh_neg_z_nonzero` | `z_nonzero` | Z 保留位非 0 | `z`（备选 flag/value） | RFC 1035 §4.1.1+设计§3.2 |
| `doh_neg_rdlength_mismatch` | `rdlength_mismatch` | Answer RDLENGTH≠RDATA 实际字节 | `rdlength`（备选 length/answer） | RFC 1035 §4.1.3+设计§3.3 |
| `doh_neg_ancount_mismatch` | `ancount_mismatch` | ANCOUNT≠声明答案数 | `ancount`（备选 count） | RFC 1035 §4.1.1+设计§3.2 |
| `doh_neg_qdcount_multi` | `qdcount_multi` | QDCOUNT>1（本版恒 1） | `qdcount`（备选 question） | 设计§3.2 决策 |
| `doh_neg_dns_id_range` | `dns_id_range` | dns_id 声明 65536（16-bit 上界 +1 越界） | `id`（备选 range/value） | RFC 1035 §4.1.1+需求 v1.3 边界相邻值 |
| `doh_neg_ttl_range` | `ttl_range` | TTL 声明 4294967296（2^32 越界） | `ttl`（备选 range/value） | RFC 1035 §4.1.3+需求 v1.3 边界相邻值 |
| `doh_neg_qtype_token` | `qtype_token` | qtype/qclass 非数字 token（如 BOGUS） | `qtype`（备选 value/token） | RFC 1035 §3.2.2+设计§3.3 v2.2 决策 |

**合并说明（C4 修复，v2.2 保留）**：`body_missing`（POST 无 body）与 `http200_no_dns`（2xx 无 DNS 体）两个分支不设独立行/ID——分别由 `content_length` 与 `response_question` 行覆盖，锚词已并入目标行；**v2.2 扩面**新增 8 行负例（65535 上界、Opcode、GET Content-Type、响应 QR、Z 位、RDLENGTH、ANCOUNT、QDCOUNT>1），v2.2.1 起 26 行与用例文档 §5 表一一对应、同序。

**不得误报为 planner error 的合法协议事件**：HTTP 400/404/415 错误响应本身（正例错误形态）、DNS NXDOMAIN/SERVFAIL RCODE（合法 DNS 响应）、TTL=0、Cache-Control 缺省（§5.1 SHOULD 非 MUST，本版 fixture 恒显式携带但实现不得把缺失当错）、POST 与 GET 并存（多事务）。只有配置、线格式、长度或关联错误进入负例。

## 8. 边界

- **DNS ID**：0x0000 与 0xFFFF 满值均为合法（RFC 1035 §4.1.1 未保留）；`doh_dns_id_boundary` 两变体断言请求/响应 ID 精确同值。
- **QNAME**：全名最长 255 字节、单标签最长 63 字节（RFC 1035 §3.1）；`doh_dns_qname_max` 构造 255 字节上界名与 63 字节单标签；根名（仅零字节根标签，`doh_dns_question_root`）为最短合法 QNAME。
- **大响应跨 MSS**：`doh_mss_large_response` 用多 Answer/长 TXT 使响应跨多个 TCP 分段，必须按 Content-Length/重组流还原 DNS wire 后再断言；**分段边界不是 DNS 消息边界**。
- **TTL/缓存头边界**：TTL=0 与 TTL=0xFFFFFFFF（4294967295）均合法（32 位无符号），Cache-Control max-age 相应取 0/4294967295；实测 tshark 3.6.14 可解析满值 TTL（`dns.resp.ttl=4294967295`）。
- **空 QUESTION**：QDCOUNT=0 拒绝，进负例——依据为**本版 validator 设计决策**（RFC 1035 未定义空 Question 的合法消息，RFC 8484 亦未定义），不冒充 RFC 语义要求。
- **v4/v6**：IPv4/IPv6 独立 fixture，同一逻辑 DNS wire 字节必须一致，仅外层 IP 头与偏移（54/74）不同；不得从 IPv4 默认值推导 IPv6 地址。
- **多会话**：≥2 个独立四元组，DNS ID、QNAME、事务状态互不串用；会话间包序按多会话展开。
- **base64url 长度**：GET URI 字符数（`ceil(L*4/3)`）不等于 DNS wire 字节数，Content-Length 不替代解码后长度检查。
- DNS wire 上界 **65535 字节**（RFC 8484 §6 最大消息）：**上界由实现校验**，设独立负例 `doh_neg_wire_over_max`（声明总长 >65535 的配置被 validator 拒绝，锚 `length`）；大消息**正例代理**用 QNAME 255 上界 + MSS 大响应分段覆盖接近上界的形态，本版 fixture 不构造完整 65535B 单消息；不得产生回绕长度或超量分配。

## 9. 原子 ID 与完成定义

语义用例 ID 以**用例文档 §2 为唯一权威**（v1.2/v1.3：行为面全枚举，不做设计↔用例一对一映射）；设计、testcase 与未来 `doh.json` 使用同一组唯一 ID 与顺序；当前 JSON 另有不计入的 `doh_neg_unregistered` 占位。用例数量由可测试行为面决定（DNS wire 头 13 字段 × 值域边界 × HTTP 两映射 × 载体 × 错误分支 × 场景，量级 100+），见用例文档 §2 全量表。

**ID 权威（v1.2/v1.3 行为面枚举）**：语义用例 ID 清单以**用例文档 §2 为唯一权威**（v2.2 起按可测试行为面全枚举扩量，正例 84 + 负例 26 = **110 条**，量级随行为面继续增长）；本节不再维护 ID 逐条表（v2.0.1 的 38 ID 表见 git 历史）。设计、用例文档与未来 `doh.json` 使用同一组唯一 ID 与顺序。

完成定义：注册 `tcp→http→doh` 层链；逐字段生成并验证 §3 的 HTTP 头、base64url、DNS wire 头/Question/Answer/SOA/SVCB 与缓存头；GET/POST 两映射、自动应答（含非 2xx 空 body 确定性规则）、混合 GET/POST 会话（Content-Type 逐事务）、多事务 keep-alive（逐请求 Connection 策略）、多会话展开与并发会话、IPv4/IPv6、非默认端口、MSS 分段与边界均可观测；DNS wire 65535 上界由 validator 校验（`doh_neg_wire_over_max` 负例 + QNAME 255/MSS 代理）；用例文档 §2 全量语义用例（现 110 条 = 84 正 + 26 负）正负断言与错误传播完成；未注册阶段只接受 `unknown layer` 占位。**包数公式（H3 统一）**：每连接 = 3（握手）+ N（承载 HTTP 消息的 TCP 分段数）+ 4（挥手，本引擎 teardown 序列 FIN|ACK→ACK→FIN|ACK→ACK 共 4 帧，实现期校准值非 RFC 消息数）；请求+响应各 1 段时 N=2 → 单事务 **9**；M 笔事务同连接（每笔各 1 段）= 7 + 2M；多会话 = 各连接之和。同引擎 `http` 层已实现用例（hls/http_flv）实测印证：单事务 9、2 事务 11、3 事务 13、4 事务 15（公式与产出无"一笔裸 ACK"差值；testcase §1/§2 已按此统一）。

## 10. 修订记录

- v1.0.0（2026-08-20）：旧稿首版（14 正 + 6 负：含 http2_tls_streams、http3_quic_streams、tls_opaque_carrier、multi_stream_interleaving、pcap_nic 等 ID）。
- v2.0.0（2026-08-31）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写/review，取代 2026-08-20 旧稿（旧稿见 git 历史）。对照 RFC 8484/1035/4648/7230 全文逐节校准：载体收敛为 **HTTP/1.1 明文主 profile `doh_http1_plain`**（HTTP/2/3/TLS 降为 §1 未注册边界——本生成器 `http` 层默认明文链路，无 TLS key log 不断言解密内容）；用例按 v1.1 原子原则从 20 条重排为 38 条（24 正 + 14 负）——新增 DNS 头逐字段（`doh_dns_header_query`）、Question 分类型（A/AAAA/HTTPS/根名）、TTL/ID/QNAME 边界、缓存头、400/404/415 错误响应形态、多事务 keep-alive、MSS 大响应、多会话；删除 http2/3/TLS/pcap_nic/多流（本版边界）；GET 断言改用实测 `http.request.uri.query.parameter`；以本机 tshark 3.6.14 构造 pcap 实证"HTTP/1.1 明文 application/dns-message 自动内层解码 DNS（dns.id/dns.qry.name/dns.qry.type/dns.qry.class/dns.count.*/dns.resp.ttl/dns.a/dns.flags.rcode）"并固化为断言基线；RFC 8484 §4.2.1 错误状态码（400/404/415）、§5.1 缓存（max-age ≤ 最小 TTL）、§6 base64url 无 padding 逐条入文并给出章节出处。状态：**待独立隔离审查**。
- v2.0.1（2026-08-31）：按独立对抗审查 24 项问题清单修复（4C/5H/9M/6L），状态改为"修复完成，待原审查员复验关闭"。关键修复：①【C3】§1 明文 HTTP/1.1 如实声明为规范外偏差（RFC 8484 §5 https scheme MUST；原"§4.2 明示 HTTP/1.1 可用"错引更正为 §5.2，并注明其 TLS 语境）；②【C4】§7 负例表删 `doh_neg_body_missing`/`doh_neg_http200_no_dns` 两行，分支与候选锚词真正并入 `doh_neg_content_length`（`body`/`dns`）与 `doh_neg_response_question`（`body`/`wire`），14 行与 §9 ID 一一对应；③【H1】§3.1/§5/§6 补非 2xx 状态码通道（`response.status`）与自动应答确定性规则（非 2xx 空 body、无 DNS wire），400/404 出处改 RFC 7231 §6.5.1/§6.5.4 通用语义 + 本版映射决策（§4.2.1 原文不提 400/404）；④【H2】钉死逐请求 Connection 策略（每笔 keep-alive、末笔按配置）；⑤【H4】retry 语义改正：401 同服务器重试、415/406 换服务器重试（RFC 8484 §4.2.1 原文，原稿把 401 归入换服务器为反向错引）；⑥【H5】wire_fault 枚举重排为 14 值与 14 负例 ID 一一对应（删 `body_not_dns`、拆 `truncated` 为 `b64_short`/`dns_header_short`/`question_truncated`，§7 表增注入口列）；⑦【M1】§3.2 声明 13 头字段逐字段覆盖，AA/TC/Z/NSCOUNT/ARCOUNT 显式断言（按 tshark 实测发射帧分布）；⑧【M3】QDCOUNT=0 拒绝依据改为本版 validator 设计决策；⑨【M4】响应示例出处 §4.1.1→§4.2.2；⑩【M5】场景⑤"§4.2 多流/复用"错引改 RFC 7230 §6.3 keep-alive 多事务；⑪【M6】§3.2/§5 补 DNS ID=0 SHOULD（RFC 8484 §4.1）的有意偏离声明；⑫【M7】GET Content-Length: 0 标注为本版固定形态（RFC 7230 §3.3.2 允许）；⑬【M2】§8/testcase §6 同步声明 65535 上界由实现校验、测试用 QNAME 255+MSS 分段代理；⑭【L1/L2/L3/L4/L5】base64url 字母表表述校准、两条截断路径显式区分、场景表补响应侧归属、占位拒绝不得报告通过（§1 原有声明复核保留）、14 负例按五类错误打标（每类 ≥1）；⑮【M9】配套 `cases/doh.json` 占位注记数字改 38（24 正 + 14 负）、`dst_port` 443→80 与主 profile 明文调试端口对齐（占位不发包，文档一致为先）。
