# DOH（DNS over HTTPS / RFC 8484）设计契约

> 版本：v2.0.1（设计阶段）
> 日期：2026-08-31
> 状态：**独立隔离对抗审查已完成**（按《协议设计文档与用例文档需求文档 v1.1》§3 流程：独立审查 agent 三向审计 24 项清单 → 修复 → 复验 clean（24/24 关闭，含 1 条不阻断 LOW 措辞备注的同步修正）；审查/修复记录见 §10 修订记录 v2.0.0/v2.0.1）。
> 配套文件：`docs/protocol-designs/66-doh-testcase.md`、`trafficgen/test/protocol_pcap/cases/doh.json`（当前 JSON 仅含注册前置占位，本版不写文件、不改代码；占位 dst_port 已与主 profile 对齐为 80）
> 规范基线：**RFC 8484**（DNS Queries over HTTPS，2018-10，按章节号引用）；**RFC 1035**（DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION，§3.1/§3.2/§4.1.1/§4.1.2 QNAME 与 wire 格式）；RFC 4648（base64url，§5）；RFC 7230（HTTP/1.1 消息语法与路由，§6.3 长连接/§6.3.1 请求与响应配对）；RFC 7231（HTTP/1.1 语义，§6.5.1 400/§6.5.4 404/§6.5.13 415）；RFC 9110（HTTP 语义，Cache-Control 缓存头）。
> 修订记录：v2.0.1（2026-08-31）：按独立对抗审查 24 项清单修复（4C/5H/9M/6L），关键项：错误状态码出处改 RFC 7231+本版映射决策、§5.2 错引更正并如实声明明文偏差、负例表去重与 wire_fault 14 值对齐、401/415/406 retry 语义改正、packet_count 公式统一为 3+N+4（详见 §10）。v2.0.0（2026-08-31）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写/review，取代 2026-08-20 旧稿（旧稿见 git 历史）。

## 1. 范围、profile 和未注册边界

本版定义 RFC 8484 的 DNS over HTTPS（DOH）明文链路：**HTTP/1.1 明文载体**（TCP）之上的 DNS wire message 的 GET/POST 两种映射、`application/dns-message` 媒体类型、GET 的 base64url（RFC 4648 §5，无填充）查询参数编码、HTTP 头逐项规则、DNS wire message 的 12 字节头与 Question 编码（RFC 1035）、缓存头（RFC 8484 §5.1）、错误响应形态（RFC 8484 §4.2.1 非 2xx 不含 DNS 回复；具体状态码语义按 RFC 7231 + 本版映射决策，见 §3.1）、IPv4/IPv6、多会话与多事务。

| profile（协议档案） | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `doh_http1_plain`（主 profile） | TCP + HTTP/1.1 明文（调试端口默认 80） | POST/GET、`application/dns-message`、base64url、DNS wire 头/Question/Answer、缓存头、400/404/415 错误响应 | 真实 DNS 解析成功/失败、上游递归服务器语义、EDNS/DNSSEC 扩展记录语义正确性 |
| `doh_https_boundary` | TLS/TCP（端口 443） | 仅边界声明，不设语义用例 | 解密 TLS 后声称看见 HTTP 头或 DNS wire（本生成器无 key log） |
| `doh_http2_boundary` / `doh_http3_boundary` | HTTP/2（TLS）/ HTTP/3（QUIC） | 仅边界声明 | 明文 HTTP/2/3 或 QUIC stream 重组断言 |

**载体决策与理由**：本生成器 `http` 层默认产出 HTTP/1.1 明文链路（HTTP 语义、Content-Length、keep-alive 由 `http` 层承载，与 `hls`/`cwmp` 同款分层先例），因此 DOH 主线 profile 为 `doh_http1_plain`。**如实声明偏差**：RFC 8484 §5 要求 DoH 使用 https scheme（"MUST use the https URI scheme"），本生成器 `http` 层只产明文 HTTP/1.1，故主 profile `doh_http1_plain` 属**测试用途的规范外偏差**；媒体类型/DNS wire/URI 模板仍按 RFC 8484 §6/§4.1 执行；TLS/HTTP2/3 为边界。RFC 8484 §5.2 的原文（"Earlier versions of HTTP are capable of conveying the semantic requirements of this specification, but may result in very poor performance"）出自 §5.2 且语境是 TLS 内 HTTP/1.1 vs HTTP/2 的比较，**不构成对明文 HTTP/1.1 的规范允许**——不得再把该句当"明文可用"依据。HTTPS/TLS 与 HTTP/2/3 均为**未注册边界**：本版不实现、不声称、不许静默转换，明文 HTTP/2/3 不是 DoH 标准用法（RFC 8484 的 HTTP/2/3 均指在 TLS 上的加密链路），故无 TLS key log 时无法断言内部字段。

**未注册边界**：当前仓库没有注册 `doh` layer（层）、planner（规划器）、validator（校验器）或生成器。`cases/doh.json` 只保留一个不计入语义 ID 的注册前置占位 `doh_neg_unregistered`（`expect_error=true`、`error_contains` 精确为 `unknown layer`）。占位的拒绝、0 包或空 PCAP 不得报告为 DOH 行为通过；注册后按本文 §9 与用例文档 §2 的同一顺序替换为语义用例。

**动态值不硬编码**：DNS ID、随机查询名 label、随机端口为运行期或配置值，断言用 `nonzero`、`same_as_packet`、`distinct_values` 与稳定 token 字节；QNAME 主体、QTYPE、QCLASS、TTL、RCODE、应答内容属预配置值，允许 fixture 显式给出。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[tcp, http, doh]`（引擎自动补 `ip`；需要显式地址族时写 `[ip, tcp, http, doh]` 或 IPv6 等价链）。HTTP 语义（请求行/头/Content-Length/keep-alive）由 `http` 层承载，`doh` 终结层在其上产出 DNS wire 与 URI/base64url 编码与事务序列。

端口与 profile 对应：

| profile | 默认端口 | 说明 |
|---|---:|---|
| `doh_http1_plain` | 80 | 明文调试链路；端口可由配置显式覆盖（如 8080），planner 不得静默改写 |
| `doh_https_boundary` | 443 | 仅边界声明；未解密时不得断言 HTTP/DNS 内容 |

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

**GET 请求**（DNS wire 编为 base64url 无填充后放入 `dns` 查询参数，§4.1 URI 模板 `/dns-query{?dns}`、§6 无 padding 硬性要求；请求不携带 body；GET 的 `Content-Length: 0` 为**本版固定形态**——RFC 7230 §3.3.2 允许无 body 请求显式声明 0 长度，RFC 8484 §4.1/§6 不要求 GET 携带该头，不得挂靠为规范要求）：

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
| 请求行 | GET/POST | `POST /dns-query HTTP/1.1` / `GET /dns-query?dns=<b64> HTTP/1.1` | §4.1 URI 模板；`dns` 为唯一查询参数 |
| `Host` | 请求 | dst_ip 或显式配置（默认 dst_ip） | RFC 7230 §5.4；生成器 `http` 层缺省 |
| `Content-Type` | 请求（POST）/响应 | `application/dns-message` | §6 媒体类型注册；请求用 POST 时表示 body 媒体类型，响应总是携带 |
| `Accept` | 请求 | `application/dns-message` | §4.1 客户端 SHOULD 携带；本版默认带 |
| `Content-Length` | 请求（POST）/响应 | body 字节数（十进制 ASCII） | RFC 7230 §3.3.2；POST 请求与响应均等于 DNS wire 字节数；GET 请求为 0（本版固定形态，见 §3.1 GET 注，非 RFC 8484 规范要求） |
| `Connection` | 请求（每笔） | `keep-alive`（多事务每笔请求均带；末笔按 close/keep-alive 配置决定，默认 close）/ `close`（单事务即末笔） | RFC 7230 §6.3；**本版钉死策略（§5）**：多事务下逐请求均显式携带 `Connection: keep-alive`，仅末笔事务按配置决定由 keep-alive 改为 close |
| `Cache-Control` | 响应 | `max-age=<秒>` | §5.1（见 §3.6） |

错误响应形态：**非 2xx 响应不得包含对原查询的 DNS 回复**（RFC 8484 §4.2.1），自动应答产空 body、无 DNS wire（§5 确定性规则）。状态码语义出处：**400**（RFC 7231 §6.5.1 通用语义 + 本版映射决策：GET 缺 `dns` 参数时映射为 400）、**404**（RFC 7231 §6.5.4 通用语义 + 本版映射决策：URI 无对应查询路径）、**415**（RFC 7231 §6.5.13 通用语义 + 本版映射决策：请求媒体类型不支持）——RFC 8484 §4.2.1 原文不提 400/404（其状态码语境限于 401/406/415 的客户端重试建议，见 §5），故 400/404 的语义不挂靠 §4.2.1。非 2xx 状态经事件 `response.status`（或 `http` 子映射）声明（§6 配置通道）。

### 3.2 DNS wire header（RFC 1035 §4.1.1，12 字节，全大端）

| 字段 | 偏移 | 宽度 | 值域 | 本版默认 | 说明 |
|---|---|---|---:|---|---|
| ID（Transaction ID） | 0 | 2B | 0x0000–0xFFFF | 配置/随机 | 请求/响应关联标识，响应必须回带同值 |
| QR | 2 bit15 | 1bit | 0=查询,1=响应 | 0（请求）/1（响应） | Flags 高 bit |
| Opcode | 2 bit14–11 | 4bit | 0–15 | 0（QUERY） | 本版仅 0 |
| AA | 2 bit10 | 1bit | 0/1 | 0 | 响应侧可选 |
| TC | 2 bit9 | 1bit | 0/1 | 0 | 截断位，本版不置位 |
| RD | 2 bit8 | 1bit | 0/1 | 1（请求） | 期望递归 |
| RA | 2 bit7 | 1bit | 0/1 | 0（请求）/1（响应） | 递归可用 |
| Z | 2 bit6–4 | 3bit | 0 | 0 | 保留必为 0 |
| RCODE | 2 bit3–0 | 4bit | 0–15 | 0/2/3 | 响应码：0 NOERROR、2 SERVFAIL、3 NXDOMAIN（§4.1.1） |
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

QNAME 编码规则（§3.1）：域名被编码为 label 序列，每个 label 前导 1 字节长度前缀（0–63），**以 1 字节 0x00 根标签终止**；全名（含所有长度前缀与根标签）最长 255 字节；单标签最长 63 字节；不压缩（本版 query/response 均不用压缩指针，offset 指向 name 域本身的压缩在本版不产生）。

QTYPE/QCLASS 值（§3.2.2/§3.2.3）：QTYPE 1=A、28=AAAA、65=HTTPS（SVCB/HTTPS 类型，RFC 9460）、15=MX、16=TXT 等；QCLASS 1=IN。本版 fixture 覆盖 A/AAAA/HTTPS（现网解析器典型查询）。

Answer 编码（§4.1.3，响应侧）：`NAME`（本版为完整 QNAME 或压缩指针——压缩指针仅响应侧允许，本版响应回带完整 QNAME）+ `TYPE` 2B + `CLASS` 2B + `TTL` 4B + `RDLENGTH` 2B + `RDATA` 变长。A 记录 RDATA=4B 大端 IPv4；AAAA 记录 RDATA=16B IPv6；TTL 为 32 位无符号秒（0x00000000–0xFFFFFFFF）。

### 3.4 base64url 编码（RFC 4648 §5 / RFC 8484 §6）

GET 的 `dns` 查询参数值 = DNS wire message 的 base64url 编码：字母表 `A-Z a-z 0-9 - _`（`-`/`_` 替代标准 base64 的 `+`/`/`），**去除 `=` padding（§6 MUST NOT be included）**；未填充长度公式 `len_b64 = ceil(len_wire * 4 / 3)`。解码侧必须逐字节验证：出现**标准 base64 字母表字符（`+`/`/`）、padding `=`**、或任何非 base64url 字母表字符、或解码后字节数 <12（不足 DNS 头）均属错误（进负例，§7）。**两条截断路径显式区分（L2 修复）**：`b64_short`（base64 解码**产出** <12B，故障在解码链）与 `dns_header_short`（POST body **原始**字节 <12B，不经 base64 解码链）是两条不同的校验路径，实现不得合并成一条。

### 3.5 每消息长度公式

- DNS wire 请求：`L = 12 + QNAME_len + 4`，其中 `QNAME_len = len(name) + 2`（`len(name)` 为点分展示长度；推导：标签字符数 = len − (标签数−1)，加每标签 1B 长度前缀（标签数）+ 根标签 1B → len − n + 1 + n + 1 = len + 2，与标签数无关）。例：`www.example.com`（展示长度 15）→ QNAME_len = 17 → L = 12+17+4 = **33**（tshark 实测 http.content_length=33 印证）。
- DNS wire 响应：`L = 12 + QNAME_len + 4 + Σ_answer (QNAME_len + 10 + RDLENGTH)`（无压缩时；NAME/TYPE/CLASS/TTL/RDLENGTH = QNAME_len + 2+2+4+2）。例：上例 + 一条 A 答案（RDLENGTH=4）→ L = 12+17+4 + (17+10+4) = **64**（tshark 实测 http.content_length=64 印证）。
- POST 请求 `Content-Length = L`；GET 查询参数长度 = `ceil(L*4/3)`（**不替代 Content-Length，GET 请求无 body**）；响应 `Content-Length = L_response`。
- 帧长上界：`frame_len ≤ 14(eth) + 20/40(IP) + 20(TCP) + HTTP 头长 + Content-Length`；跨 MSS 分段规则见 §8。

### 3.6 缓存头（RFC 8484 §5.1）

服务器 SHOULD 给响应显式 HTTP 新鲜度生命周期，且**必须 ≤ 答案区最小 TTL，等于为 RECOMMENDED**；负响应（Answer 空且 Authority 含 SOA）新鲜度不得大于 SOA MINIMUM；客户端必须考虑 `Age` 头（TTL − Age）。本版 fixture：`Cache-Control: max-age=<配置的 ttl_sec>`，默认等于答案最小 TTL；TTL=0 时 `max-age=0`；TTL=0xFFFFFFFF 时 `max-age=4294967295`（见 §8 边界）。POST 响应按 §5.1 默认不可缓存，本版响应恒为显式 `max-age`，不模拟缓存缺失形态。

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

**14 个负例按五类错误打标（L5 修复）**——与 §7 表、§9 ID 表逐一对齐，每类 ≥1：
- **配置类（2）**：`doh_neg_query_missing`（GET 缺 `dns` 参数）、`doh_neg_carrier_port`（层链/端口载体矛盾）；
- **线格式类（7）**：`doh_neg_base64_invalid`、`doh_neg_base64_padding`、`doh_neg_base64_truncated`、`doh_neg_dns_header_short`、`doh_neg_dns_qdcount_zero`、`doh_neg_dns_qname_overflow`、`doh_neg_dns_question_truncated`（base64url 解码与 DNS wire 编码）；
- **状态机/HTTP 语义类（2）**：`doh_neg_content_type`（媒体类型非法）、`doh_neg_method`（方法不在 GET/POST 域，违反 §4.1 方法约束）；
- **关联类（2）**：`doh_neg_response_id`（ID 错）、`doh_neg_response_question`（Question 错配/2xx 无 DNS 体合并分支）；
- **长度类（1）**：`doh_neg_content_length`（Content-Length≠body 字节，含 POST 无 body 合并分支）。

**五层覆盖逐层结论**：功能层——GET/POST 两映射、DNS 头 12B 逐字段、Question 各查询类型、Answer 结构、RCODE 值域、缓存头、错误状态响应全正例；每类错误分支负例（§7）。性能层——大响应跨 MSS 分段重组（`doh_mss_large_response`）、QNAME 255/63 上界、DNS 头计数上界。数据场景层——DNS ID 0/满值、TTL 0/满值、QCLASS/QTYPE 值、base64url 编码变体、非法值拒绝。地址与流层——IPv4/IPv6 独立 fixture、单流基线、多会话双四元组（`doh_multi_session`）；**流关联（控制流派生数据流）显式不适用**：DoH 是纯请求/响应查询协议，无控制流派生媒体/数据流，RFC 8484 全文无流关联概念；**多流（会话内部并发 HTTP/2 stream）显式不适用**：本版仅 HTTP/1.1 明文，HTTP/1.1 一个连接内请求/响应严格配对（RFC 7230 §6.3.1），无 stream 概念（§1 边界声明）。业务层——解析器查询、HTTPS 记录、缓存策略、长连接多查询、POST 变体、IPv6 均为现网日常，优先于教科书全类型遍历。

## 5. 消息/事务模型与状态机

**事务定义**：DOH 事务 = 同一 HTTP 连接内一次完整的 HTTP 请求/响应对（RFC 8484 §4.1 的 query/response 交互）。**DNS 事务关联 = DNS ID**：响应必须回带与请求相同的 16-bit ID（RFC 1035 §4.1.1）——DNS ID 在 HTTP 层映射（body 内或 URI query 解码后），与 HTTP/1.1 请求/响应配对（RFC 7230 §6.3.1，先到先配、无 pipelining）共同构成事务关联。**多事务** = 一个 TCP 连接内多笔查询按序执行（keep-alive），每笔独立 DNS ID、独立 QNAME，请求/响应严格交替。**事务交互**示例：同一连接先查 A 再查 AAAA（互不依赖，但依赖同一连接状态）；缓存头 max-age 影响客户端后续是否重查（本版不模拟客户端缓存决策，只产出响应头）。

**逐请求 Connection 策略（钉死，H2 修复）**：多事务连接内**每笔 HTTP 请求均携带 `Connection: keep-alive`**（RFC 7230 §6.3 长连接语义），仅**末笔事务按 close/keep-alive 配置决定**（默认 `close`）——本策略为生成器产线依据（§3.1 头表、testcase 用例 15 按此断言），废弃"只有首请求带 keep-alive"的无依据表述。

**DNS ID=0 的 SHOULD 与有意偏离（M6 修复）**：RFC 8484 §4.1 建议 DoH 客户端将 DNS ID 置 0（SHOULD，原文 "SHOULD use a DNS ID of 0 in every DNS request"，缓存友好——HTTP 层已提供事务关联，变化的 ID 会使语义等价的查询被分开缓存）；本版允许配置/随机 ID 以便断言请求/响应关联与 ID 边界（正例 10/23），属对该 SHOULD 的**有意偏离**（偏离 SHOULD 不构成不合规，但在此显式声明）。

会话状态机（HTTP/1.1 明文，TCP 层）：

| 状态 | 允许事件 | 必须保持 |
|---|---|---|
| `ConnectPending` | TCP 三次握手完成 | 握手后首帧是 HTTP 请求（GET 或 POST） |
| `RequestSent` | 发送 HTTP 请求（含 DNS wire） | POST：Content-Length=body 字节数；GET：`dns` 参数无 padding base64url、无 body |
| `ResponsePending` | 收到 HTTP 响应 | 响应 Content-Type=application/dns-message（2xx 时）；响应 DNS ID=请求 ID；2xx 必须携带 DNS body，非 2xx 不得携带（§4.2.1）；**非 2xx 时自动应答产空 body、无 DNS wire**（§5 确定性规则） |
| `KeepAlive`（多事务） | 下一笔请求（DNS ID 递增/独立） | 请求/响应严格交替，不得 pipelining（RFC 7230 §6.3.1 本版顺序执行）；**逐请求 Connection 策略钉死**：每笔请求均显式携带 `Connection: keep-alive`，仅末笔事务按 close/keep-alive 配置决定（默认 close），保证请求/响应严格配对不靠隐式推断 |
| `Terminating` | FIN 挥手 | 全部事务完成后才挥手；失败连接按 TCP 语义终止 |
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

形状要点：`sessions[]` = 统一术语的**事件编排会话**（每个自带四元组与事件序列，多会话展开按序整块回放，第二会话包号起点 = 前会话总包数 + 1）；`events[]` = 会话的**事件序列**，元素为一笔 DNS 查询事务（`kind: query`）；`method`/`uri` 为会话级 HTTP 骨架默认值，可被事件 `http` 子映射覆盖（HTTP 头覆盖是显式写全的通道）；**`response.status` 为非 2xx 状态码声明通道（H1 修复）**——缺省 200；声明 400/404/415 等非 2xx 时自动应答只产状态行/头 + 空 body、无 DNS wire（§3.1/§5 确定性规则，正例 18/19/20 由此配置，也可复用 `http` 子映射 `response_status_code` 等价表达）；`dns_id` 支持 fixed/inc/rand 策略，边界用例显式固定 0/65535；`response` 声明自动应答内容（rcode/answers），answers 为空时响应仅含头+Question（NXDOMAIN/SERVFAIL 形态）；**逐请求 Connection 策略**：多事务每笔请求默认 `Connection: keep-alive`，末笔按 close/keep-alive 配置决定（默认 close，§5 钉死）。`wire_fault` 仅负例注入口，**取值 14 个、与 §7 表/§9 ID 表的 14 个负例一一对应（H5 修复）**：`query_missing`/`base64`/`padding`/`b64_short`/`dns_header_short`/`qdcount`/`qname`/`question_truncated`/`content_type`/`method`/`content_length`/`carrier`/`response_id`/`response_question`（旧枚举的 `truncated` 拆为 `b64_short`/`dns_header_short`/`question_truncated` 三个取值、`body_not_dns` 删除——其对应用例已并入 `content_length`/`response_question` 分支），不得成为线上字段。`qclass` 默认 IN。**驱动顺序**：events[] 按序逐笔回放，自动应答随事件即时补响应；多会话整块展开。并发会话（`concurrent: true`）本版不适用——HTTP/1.1 会话本身单连接串行，双会话用多会话展开表达。

## 7. 错误处理（负例锚词表）

以下输入必须由 planner/validator 拒绝并传播为 task error（任务错误），不得产出成功 PCAP、`completed/0 packet` 或仅 TCP/HTTP 外壳的假成功。锚词（anchor word）为 `error_contains` 断言字面值，与用例文档 §5 一一对应：

| 负例 ID | `wire_fault` 注入口（H5） | 故障输入（方向） | `error_contains` 候选锚词 |
|---|---|---|---|
| `doh_neg_query_missing` | `query_missing` | GET 查询缺 `dns` 参数（配置/生成侧未携带） | `dns`、`query` 或 `parameter` |
| `doh_neg_base64_invalid` | `base64` | base64url 含非法字符（标准 base64 字母表字符 `+`/`/`、padding `=` 或非字母表字节） | `base64`、`url` 或 `decode` |
| `doh_neg_base64_padding` | `padding` | base64url 带 `=` padding（RFC 8484 §6 禁） | `base64`、`padding` 或 `url` |
| `doh_neg_base64_truncated` | `b64_short` | **base64url 解码产出 <12B**（不足 DNS 头；故障在解码链，见 §3.4 与下行 dns_header_short 的显式区分） | `decode`、`truncate` 或 `length` |
| `doh_neg_dns_header_short` | `dns_header_short` | **POST body 原始字节 <12B**（头不足；不经 base64 解码链） | `dns`、`header` 或 `length` |
| `doh_neg_dns_qdcount_zero` | `qdcount` | QDCOUNT=0（空 QUESTION 拒绝——**本版 validator 设计决策**：RFC 1035 未定义空 Question 的合法消息，RFC 8484 亦未定义） | `question`、`qdcount` 或 `dns` |
| `doh_neg_dns_qname_overflow` | `qname` | QNAME 全名 >255 或单标签 >63 | `qname`、`label` 或 `length` |
| `doh_neg_dns_question_truncated` | `question_truncated` | Question 编码截断（QNAME 未以零标签终止、QTYPE/QCLASS 缺失） | `question`、`wire` 或 `length` |
| `doh_neg_content_type` | `content_type` | 请求/响应 Content-Type 非 `application/dns-message`（如 text/plain、application/dns、application/json） | `content-type`、`media` 或 `type` |
| `doh_neg_method` | `method` | HTTP 方法非 POST/GET（PUT/DELETE 等） | `method` 或 `http` |
| `doh_neg_content_length` | `content_length` | POST Content-Length ≠ DNS wire 字节数（body 缺失/多余；**并入分支：POST 无 body**——原 `doh_neg_body_missing`，候选锚词 `body`/`dns` 已并入本行） | `content-length`、`length`、`body` 或 `dns` |
| `doh_neg_carrier_port` | `carrier` | 层链缺 http（tcp→doh 直连）、端口/载体声明矛盾 | `carrier`、`port` 或 `layer` |
| `doh_neg_response_id` | `response_id` | 响应 DNS ID ≠ 请求 ID（关联错） | `id`、`match` 或 `correlation` |
| `doh_neg_response_question` | `response_question` | 响应 Question 与请求不符（QNAME/QTYPE/QCLASS 错配；**并入分支：2xx 响应无/非 DNS body**——原 `doh_neg_http200_no_dns`，候选锚词 `body`/`wire` 已并入本行） | `question`、`match`、`correlation`、`body` 或 `wire` |

**合并说明（C4 修复）**：`doh_neg_body_missing`（POST 无 body）与 `doh_neg_http200_no_dns`（2xx 无 DNS body）不设独立行/ID——分别并入 `doh_neg_content_length`（POST 无 body 由 Content-Length 校验覆盖）与 `doh_neg_response_question`（2xx 无 DNS body 由响应 Question 校验覆盖），两分支的候选锚词已真正并入目标行锚词列（见上表加粗），本表 14 行与 §9 的 14 个负例 ID 一一对应、同序。

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
- DNS wire 上界 **65535 字节**（RFC 8484 §6 最大消息）：**上界由实现校验**（validator 对超限配置报错进负例路径），测试侧用 QNAME 255 上界 + MSS 大响应分段**代理**覆盖接近上界的大消息，本版 fixture 不构造完整 65535B 单消息（与 testcase §6 声明同口径）；不得产生回绕长度或超量分配。

## 9. 原子 ID 与完成定义

设计、testcase 与未来 `doh.json` 必须使用同一组唯一语义 ID、同一顺序（原子用例：一个用例只验证一个协议行为；DNS 头逐字段、Question 各类型、HTTP 各规则、边界、错误分支各一）；当前 JSON 另有不计入的 `doh_neg_unregistered` 占位。共 **38 条：24 正例 + 14 负例**（数量由协议结构决定——DOH = DNS wire × HTTP 两维协议组合，超过 20 条符合 v1.1 §7 "数量由协议结构决定"）。

| # | ID | 类型 | 覆盖 |
|---:|---|---|---|
| 1 | `doh_post_ipv4_http11` | 正 | POST/IPv4 明文单流基线（Content-Type/Length/Accept、DNS wire 在 body、ID same_as） |
| 2 | `doh_get_ipv4_base64url` | 正 | GET/IPv4、`dns` 查询参数 base64url 无 padding |
| 3 | `doh_post_ipv6_http11` | 正 | POST/IPv6（ipv6.nxt=6、offset 74） |
| 4 | `doh_get_ipv6_base64url` | 正 | GET/IPv6 独立 fixture |
| 5 | `doh_dns_header_query` | 正 | DNS 头 12B 大端逐字段（ID/QR/Opcode/AA/TC/RD/RA/Z/RCODE/QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT 13 项全覆盖；AA/TC/Z/NSCOUNT/ARCOUNT 显式断言 0，按 tshark 实测发射帧分布落断言） |
| 6 | `doh_dns_question_a` | 正 | QNAME 长度前缀标签编码、QTYPE=A(1)、QCLASS=IN(1) 大端 |
| 7 | `doh_dns_question_aaaa` | 正 | QTYPE=AAAA(28) |
| 8 | `doh_dns_question_https` | 正 | QTYPE=HTTPS(65) |
| 9 | `doh_dns_question_root` | 正 | 根 QNAME（零字节根标签）最短消息 |
| 10 | `doh_dns_response_noerror` | 正 | 响应 RCODE=0、QR=1、RA=1、ANCOUNT≥1、ID same_as |
| 11 | `doh_dns_response_nxdomain` | 正 | RCODE=3、ANCOUNT=0、HTTP 200（HTTP 200 ≠ DNS 成功） |
| 12 | `doh_dns_response_servfail` | 正 | RCODE=2、ANCOUNT=0、HTTP 200 |
| 13 | `doh_dns_answer_ttl` | 正 | A 答案 NAME/TYPE/CLASS/TTL/RDLENGTH/RDATA 结构、TTL 值 |
| 14 | `doh_dns_ttl_boundary` | 正 | TTL=0 与 TTL=0xFFFFFFFF 边界 + Cache-Control 对应 |
| 15 | `doh_http_keepalive_multi_transaction` | 正 | HTTP/1.1 keep-alive 同连接多事务、请求/响应严格配对（RFC 7230 §6.3.1）；逐请求 Connection 策略：每笔均带 keep-alive、末笔按配置（§5 钉死） |
| 16 | `doh_http_content_length_exact` | 正 | POST Content-Length 精确 = DNS wire 字节数（33） |
| 17 | `doh_http_cache_control` | 正 | Cache-Control max-age = 答案最小 TTL（§5.1） |
| 18 | `doh_http_error_400` | 正 | GET 缺 `dns` 参数 → 400 空 body、无 DNS wire（非 2xx 通道 `response.status`，§5 确定性规则） |
| 19 | `doh_http_error_404` | 正 | 未知 URI → 404 空 body、无 DNS wire（`response.status` 通道） |
| 20 | `doh_http_error_415` | 正 | 媒体类型不支持 → 415 空 body、无 DNS wire（`response.status` 通道） |
| 21 | `doh_mss_large_response` | 正 | 大响应跨 MSS 分段、重组后 DNS wire 完整 |
| 22 | `doh_dns_qname_max` | 正 | QNAME 255/单标签 63 上界 |
| 23 | `doh_dns_id_boundary` | 正 | DNS ID 0x0000/0xFFFF 边界（RFC 8484 §4.1 建议 DoH 客户端 ID=0 为 SHOULD、缓存友好；本版允许配置/随机以便测关联，属有意偏离，见 §5 注） |
| 24 | `doh_multi_session` | 正 | 多会话展开双四元组、状态不串用 |
| 25 | `doh_neg_query_missing` | 负 | 缺 dns 查询参数 |
| 26 | `doh_neg_base64_invalid` | 负 | 非法 base64url 字符 |
| 27 | `doh_neg_base64_padding` | 负 | base64url 带 `=` padding |
| 28 | `doh_neg_base64_truncated` | 负 | 解码截断 <12B |
| 29 | `doh_neg_dns_header_short` | 负 | DNS 头 <12B |
| 30 | `doh_neg_dns_qdcount_zero` | 负 | QDCOUNT=0 空 QUESTION |
| 31 | `doh_neg_dns_qname_overflow` | 负 | QNAME>255/单标签>63 |
| 32 | `doh_neg_dns_question_truncated` | 负 | Question 编码截断 |
| 33 | `doh_neg_content_type` | 负 | Content-Type 非 application/dns-message |
| 34 | `doh_neg_method` | 负 | 方法非 POST/GET |
| 35 | `doh_neg_content_length` | 负 | Content-Length≠DNS body 字节 |
| 36 | `doh_neg_carrier_port` | 负 | 层链缺 http/端口载体冲突 |
| 37 | `doh_neg_response_id` | 负 | 响应 ID≠请求 ID |
| 38 | `doh_neg_response_question` | 负 | 响应 Question 错配 |

（合并说明见 §7 表后注：`doh_neg_body_missing`/`doh_neg_http200_no_dns` 不设独立 ID，分支与候选锚词已并入 `doh_neg_content_length`/`doh_neg_response_question` 两行；§7 表、本 ID 表、testcase §5 表三方 14 负例一一对应、同序。）

完成定义：注册 `tcp→http→doh` 层链；逐字段生成并验证 §3 的 HTTP 头、base64url、DNS wire 头/Question/Answer 与缓存头；GET/POST 两映射、自动应答（含非 2xx 空 body 确定性规则）、多事务 keep-alive（逐请求 Connection 策略）、多会话展开、IPv4/IPv6、MSS 分段与边界均可观测；DNS wire 65535 上界由 validator 校验（测试用 QNAME 255 + MSS 分段代理，§8）；38 个语义 ID 正负断言与错误传播完成；未注册阶段只接受 `unknown layer` 占位。**包数公式（H3 统一）**：每连接 = 3（握手）+ N（承载 HTTP 消息的 TCP 分段数）+ 4（挥手，本引擎 teardown 序列 FIN|ACK→ACK→FIN|ACK→ACK 共 4 帧，实现期校准值非 RFC 消息数）；请求+响应各 1 段时 N=2 → 单事务 **9**；M 笔事务同连接（每笔各 1 段）= 7 + 2M；多会话 = 各连接之和。同引擎 `http` 层已实现用例（hls/http_flv）实测印证：单事务 9、2 事务 11、3 事务 13、4 事务 15（公式与产出无"一笔裸 ACK"差值；testcase §1/§2 已按此统一）。

## 10. 修订记录

- v1.0.0（2026-08-20）：旧稿首版（14 正 + 6 负：含 http2_tls_streams、http3_quic_streams、tls_opaque_carrier、multi_stream_interleaving、pcap_nic 等 ID）。
- v2.0.0（2026-08-31）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写/review，取代 2026-08-20 旧稿（旧稿见 git 历史）。对照 RFC 8484/1035/4648/7230 全文逐节校准：载体收敛为 **HTTP/1.1 明文主 profile `doh_http1_plain`**（HTTP/2/3/TLS 降为 §1 未注册边界——本生成器 `http` 层默认明文链路，无 TLS key log 不断言解密内容）；用例按 v1.1 原子原则从 20 条重排为 38 条（24 正 + 14 负）——新增 DNS 头逐字段（`doh_dns_header_query`）、Question 分类型（A/AAAA/HTTPS/根名）、TTL/ID/QNAME 边界、缓存头、400/404/415 错误响应形态、多事务 keep-alive、MSS 大响应、多会话；删除 http2/3/TLS/pcap_nic/多流（本版边界）；GET 断言改用实测 `http.request.uri.query.parameter`；以本机 tshark 3.6.14 构造 pcap 实证"HTTP/1.1 明文 application/dns-message 自动内层解码 DNS（dns.id/dns.qry.name/dns.qry.type/dns.qry.class/dns.count.*/dns.resp.ttl/dns.a/dns.flags.rcode）"并固化为断言基线；RFC 8484 §4.2.1 错误状态码（400/404/415）、§5.1 缓存（max-age ≤ 最小 TTL）、§6 base64url 无 padding 逐条入文并给出章节出处。状态：**待独立隔离审查**。
- v2.0.1（2026-08-31）：按独立对抗审查 24 项问题清单修复（4C/5H/9M/6L），状态改为"修复完成，待原审查员复验关闭"。关键修复：①【C3】§1 明文 HTTP/1.1 如实声明为规范外偏差（RFC 8484 §5 https scheme MUST；原"§4.2 明示 HTTP/1.1 可用"错引更正为 §5.2，并注明其 TLS 语境）；②【C4】§7 负例表删 `doh_neg_body_missing`/`doh_neg_http200_no_dns` 两行，分支与候选锚词真正并入 `doh_neg_content_length`（`body`/`dns`）与 `doh_neg_response_question`（`body`/`wire`），14 行与 §9 ID 一一对应；③【H1】§3.1/§5/§6 补非 2xx 状态码通道（`response.status`）与自动应答确定性规则（非 2xx 空 body、无 DNS wire），400/404 出处改 RFC 7231 §6.5.1/§6.5.4 通用语义 + 本版映射决策（§4.2.1 原文不提 400/404）；④【H2】钉死逐请求 Connection 策略（每笔 keep-alive、末笔按配置）；⑤【H4】retry 语义改正：401 同服务器重试、415/406 换服务器重试（RFC 8484 §4.2.1 原文，原稿把 401 归入换服务器为反向错引）；⑥【H5】wire_fault 枚举重排为 14 值与 14 负例 ID 一一对应（删 `body_not_dns`、拆 `truncated` 为 `b64_short`/`dns_header_short`/`question_truncated`，§7 表增注入口列）；⑦【M1】§3.2 声明 13 头字段逐字段覆盖，AA/TC/Z/NSCOUNT/ARCOUNT 显式断言（按 tshark 实测发射帧分布）；⑧【M3】QDCOUNT=0 拒绝依据改为本版 validator 设计决策；⑨【M4】响应示例出处 §4.1.1→§4.2.2；⑩【M5】场景⑤"§4.2 多流/复用"错引改 RFC 7230 §6.3 keep-alive 多事务；⑪【M6】§3.2/§5 补 DNS ID=0 SHOULD（RFC 8484 §4.1）的有意偏离声明；⑫【M7】GET Content-Length: 0 标注为本版固定形态（RFC 7230 §3.3.2 允许）；⑬【M2】§8/testcase §6 同步声明 65535 上界由实现校验、测试用 QNAME 255+MSS 分段代理；⑭【L1/L2/L3/L4/L5】base64url 字母表表述校准、两条截断路径显式区分、场景表补响应侧归属、占位拒绝不得报告通过（§1 原有声明复核保留）、14 负例按五类错误打标（每类 ≥1）；⑮【M9】配套 `cases/doh.json` 占位注记数字改 38（24 正 + 14 负）、`dst_port` 443→80 与主 profile 明文调试端口对齐（占位不发包，文档一致为先）。
