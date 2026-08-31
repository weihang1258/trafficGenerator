# DOH（DNS over HTTPS / RFC 8484）测试用例契约

> 版本：v2.0.1（测试用例）
> 日期：2026-08-31
> 配套设计：`docs/protocol-designs/66-doh-design.md`
> 机器契约：`trafficgen/test/protocol_pcap/cases/doh.json`（proto key：`doh`；本版不写文件，当前 JSON 仅含注册前置占位；占位 dst_port 已对齐主 profile 明文端口 80）
> 状态：**独立隔离对抗审查已完成**（按《协议设计文档与用例文档需求文档 v1.1》§3 流程：独立审查 agent 三向审计 24 项清单 → 修复 → 复验 clean（24/24 关闭，含 1 条不阻断 LOW 措辞备注的同步修正）；审查/修复记录见 §9 修订记录 v2.0.0/v2.0.1）。
> 修订记录：v2.0.1（2026-08-31）：按独立对抗审查 24 项清单修复（4C/5H/9M/6L），关键项：`dns.count.auth_rr`/`add_rr` 单数化、根名 labels=1、packet_count 公式统一（8→9、多事务 13、双流 18）、用例 5 补 AA/TC/Z/NSCOUNT/ARCOUNT 断言、用例 1 精确长度改 nonzero、用例 15 改逐请求 keep-alive 断言、§5 表补 wire_fault 列（详见 §9）。v2.0.0（2026-08-31）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写/review，取代 2026-08-20 旧稿（旧稿见 git 历史）。

## 1. 测试原则和未注册边界

用例从设计 §2–§8 逐项派生，共 38 个唯一语义 ID：24 个正例 + 14 个负例。派生规则：设计 §3 每个编码条款、§5 每个状态/事务行为、§7 每行错误处理在本文有对应断言；断言不得超出设计（并追溯到 RFC 8484/1035）声明范围。**一个用例只验证一个协议行为**（v1.1 §7 原子原则）：DNS 头逐字段、Question 各查询类型、HTTP 每项规则、边界、错误分支各一。

当前 JSON 只保留一个 `doh_neg_unregistered` 注册前置占位：`proto=doh`、`expect_error=true`、`error_contains` 精确为 `unknown layer`；该占位不计入 38 个语义 ID，不得把拒绝、0 包或空 PCAP 报告为 DOH 行为通过。注册后移除占位，再按本文 §2 顺序补入 24 个正例与 14 个负例。

**TSHARK 实测基线（本机 3.6.14，构造 pcap 实证，非臆造）**：HTTP/1.1 明文响应 `Content-Type: application/dns-message` 且 2xx 时，tshark **自动对该 HTTP body 内层解码为 DNS**——`dns.id`、`dns.flags.response`、`dns.flags.rcode`、`dns.qry.name`、`dns.qry.type`、`dns.qry.class`、`dns.count.queries`、`dns.count.answers`、`dns.resp.ttl`、`dns.resp.type`、`dns.resp.class`、`dns.a` 均实测可见（样本：POST+GET 各一完整流，DNS 查询 `www.example.com A IN`、响应 A 记录 TTL=300）。**请求侧**（POST body 或 GET URI 参数）：POST body 同样自动内层解码（`dns.id`/`dns.qry.name` 实测可见）；**GET 请求的 URI query 解码**在 3.6.14 默认**不**自动进行（实测仅帧对 DNS 的 `dns.id` 出现在响应帧），GET 侧 DNS 断言走 `http.request.uri.query.parameter` 的 base64url 文本 + frames hex 的 body 起点偏移断言，**不臆造 GET 请求帧有 `dns.*` 字段**（解码支持可由 `-d` 强制，case JSON 实现时定并同步四件套）。响应帧 `dns.*` 断言权威。

**可用断言字段**（`tshark -G fields` 已核验，与设计 §3 一致）：`http.request.method`、`http.request.uri`、`http.request.uri.path`、`http.request.uri.query`、`http.request.uri.query.parameter`、`http.request.line`、`http.content_type`、`http.content_length_header`、`http.content_length`、`http.file_data`（FT_STRING，body 原始字节）、`http.response.code`、`http.response.line`、`http.cache_control`、`http.host`、`http.accept`、`dns.id`、`dns.flags.response`、`dns.flags.opcode`、`dns.flags.rcode`、`dns.flags.authoritative`、`dns.flags.truncated`、`dns.flags.recdesired`、`dns.flags.recavail`、`dns.flags.z`、`dns.count.queries`、`dns.count.answers`、`dns.count.auth_rr`、`dns.count.add_rr`、`dns.count.labels`、`dns.qry.name`、`dns.qry.type`、`dns.qry.class`、`dns.qry.name.len`、`dns.resp.ttl`、`dns.resp.type`、`dns.resp.class`、`dns.a`、`dns.aaaa`、`tcp.stream`、`tcp.len`、`tcp.flags.*`、`ip.version`、`ipv6.nxt`。无 `doh.*` 专用字段，不臆造。**单数字段实测声明（C1 修复）**：本机 tshark 3.6.14 的 `tshark -G fields` 只有单数 `dns.count.auth_rr`/`dns.count.add_rr`，**不存在** `dns.count.auth_rrs`/`dns.count.add_rrs` 复数形式。**发射帧分布实测（M1 修复依据）**：查询帧发射 `dns.flags.response/opcode/truncated/recdesired/z` 与 4 个 COUNT；`dns.flags.authoritative/recavail/rcode` 仅**响应帧**发射；**TC/Z 在响应帧同样发射**（实测）——AA/RA/RCODE 断言落响应帧、TC/Z 断言双侧、其余落请求帧（用例 5 据此分布，断言集为安全超集）。

**动态字段禁止硬编码**：DNS ID、随机查询名、随机端口用 `nonzero`、`distinct_values`、`same_as_packet`；QNAME 主体、QTYPE、QCLASS、TTL、RCODE、答案内容为预配置值，允许 fixture 显式给出。DNS wire 不动的内容断言用 `http.file_data` 存在性与 frames hex 前缀；DNS 头/Question 字段断言用 `dns.*` 实测字段（自动内层解码），两次互为印证。**实测字段语义注意**：`dns.qry.name.len` 在 tshark 3.6.14 为**展示字符串长度**（`www.example.com` 显示 15）、`dns.qry.name` 根名显示 `<Root>`、255 上限名显示 253——编码/长度类断言一律以 `http.content_length`（body 真实字节长）与 frames 长度前缀字节为权威，`dns.qry.name.len` 仅作辅助（§4 用例 6/9/22）。

**包数约定（H3 统一，设计 §9 完成定义同口径）**：每连接包数 = **3（握手 SYN/SYN-ACK/ACK）+ N（承载 HTTP 消息的 TCP 分段数，请求与响应分段之和）+ 4（挥手：本引擎 teardown 序列 FIN|ACK→ACK→FIN|ACK→ACK 共 4 帧——实现期校准值，非 RFC 消息数）**。**单事务**：请求+响应各 1 段时 N=2 → **9**（3+2+4）；旧约定表"8 = 3+1+4"漏计响应分段（假设请求/响应合并单段或存在一笔裸 ACK，与引擎实测不符——引擎数据段与挥手间无独立 ACK 帧），v2.0.1 起废弃。**多事务 keep-alive 同连接**：M 笔事务每笔各 1 段 → N=2M → **7 + 2M**（M=3 → 13；与 §2 旧公式 3+2N+4 在 N=事务数时等价，本版统一表述为 3+N+4 / 7+2M）。**实证**：同引擎 `http` 层已实现用例（`hls.json`/`http_flv.json`）packet_count 实测——单事务 9、2 事务 11、3 事务 13、4 事务 15，等差 2，与公式一致（请求帧 = 包 4、响应帧 = 包 5、挥手 = 包 6–9）。**多会话** = 各会话之和，第二会话起点 = 前会话总包数 + 1（设计 §5 多会话展开）。约定数字是实现基线，实现采用不同 ACK 合并/分段方式时须同步更新四件套，不得把约定数字当 RFC 消息数。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖（设计 §） | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `doh_post_ipv4_http11` | 正 | §3.1/§4①：POST/IPv4 明文单流基线 | 9 |
| 2 | `doh_get_ipv4_base64url` | 正 | §3.1/§3.4/§4①：GET `dns` 参数 base64url 无 padding | 9 |
| 3 | `doh_post_ipv6_http11` | 正 | §2/§3.1/§8：POST/IPv6（offset 74） | 9 |
| 4 | `doh_get_ipv6_base64url` | 正 | §2/§3.4/§8：GET/IPv6 独立 fixture | 9 |
| 5 | `doh_dns_header_query` | 正 | §3.2：DNS 头 12B 大端逐字段（13 项；AA/TC/Z/NSCOUNT/ARCOUNT 显式断言 0，按 tshark 发射帧分布） | 9 |
| 6 | `doh_dns_question_a` | 正 | §3.3/§4①：QNAME 标签编码、QTYPE=A、QCLASS=IN | 9 |
| 7 | `doh_dns_question_aaaa` | 正 | §3.3：QTYPE=AAAA(28) | 9 |
| 8 | `doh_dns_question_https` | 正 | §3.3：QTYPE=HTTPS(65) | 9 |
| 9 | `doh_dns_question_root` | 正 | §3.3/§8：根 QNAME 最短消息 | 9 |
| 10 | `doh_dns_response_noerror` | 正 | §3.2/§5：RCODE=0、QR=1、RA=1、ID same_as | 9 |
| 11 | `doh_dns_response_nxdomain` | 正 | §3.2/§4③/§5：RCODE=3、HTTP 200 | 9 |
| 12 | `doh_dns_response_servfail` | 正 | §3.2/§5：RCODE=2、HTTP 200 | 9 |
| 13 | `doh_dns_answer_ttl` | 正 | §3.3/§3.6：Answer 结构、TTL | 9 |
| 14 | `doh_dns_ttl_boundary` | 正 | §3.6/§8：TTL=0 与 0xFFFFFFFF | 18（9+9） |
| 15 | `doh_http_keepalive_multi_transaction` | 正 | §4⑤/§5：同连接多事务严格配对、逐请求 Connection 策略 | 13（7+2×3） |
| 16 | `doh_http_content_length_exact` | 正 | §3.1/§3.5：Content-Length=33 精确 | 9 |
| 17 | `doh_http_cache_control` | 正 | §3.6/§4④：max-age=答案最小 TTL | 9 |
| 18 | `doh_http_error_400` | 正 | §3.1/§4⑦：GET 缺 dns→400 空 body | 9 |
| 19 | `doh_http_error_404` | 正 | §3.1/§4⑦：未知 URI→404 空 body | 9 |
| 20 | `doh_http_error_415` | 正 | §3.1/§4⑦：媒体类型不支持→415 空 body | 9 |
| 21 | `doh_mss_large_response` | 正 | §8/§3.5：大响应跨 MSS 分段重组 | ≥10 校准 |
| 22 | `doh_dns_qname_max` | 正 | §8/§3.3：QNAME 255/单标签 63 上界 | 18（9+9） |
| 23 | `doh_dns_id_boundary` | 正 | §8/§3.2：ID 0x0000/0xFFFF | 18（9+9） |
| 24 | `doh_multi_session` | 正 | §4/§5/§8：多会话双四元组 | 18（9+9） |
| 25 | `doh_neg_query_missing` | 负 | §7：缺 `dns` 查询参数 | — |
| 26 | `doh_neg_base64_invalid` | 负 | §7：非法 base64url 字符 | — |
| 27 | `doh_neg_base64_padding` | 负 | §7：base64url 带 `=` padding | — |
| 28 | `doh_neg_base64_truncated` | 负 | §7：解码截断 <12B | — |
| 29 | `doh_neg_dns_header_short` | 负 | §7：DNS 头 <12B | — |
| 30 | `doh_neg_dns_qdcount_zero` | 负 | §7：QDCOUNT=0 空 QUESTION | — |
| 31 | `doh_neg_dns_qname_overflow` | 负 | §7：QNAME>255/单标签>63 | — |
| 32 | `doh_neg_dns_question_truncated` | 负 | §7：Question 编码截断 | — |
| 33 | `doh_neg_content_type` | 负 | §7：Content-Type 非 application/dns-message | — |
| 34 | `doh_neg_method` | 负 | §7：方法非 POST/GET | — |
| 35 | `doh_neg_content_length` | 负 | §7：Content-Length≠DNS body 字节 | — |
| 36 | `doh_neg_carrier_port` | 负 | §7：层链缺 http/端口载体冲突 | — |
| 37 | `doh_neg_response_id` | 负 | §7：响应 ID≠请求 ID | — |
| 38 | `doh_neg_response_question` | 负 | §7：响应 Question 错配 | — |
| — | `doh_neg_unregistered` | 占位 | 当前层注册前置 | — |

（`packet_count` 约定值按 §1 统一公式 3+N+4：**单事务 9** = 3+2+4（请求/响应各 1 段，N=2）；14/22/23 各两变体分别建流 9+9=**18**，按多会话展开处理；15 = **13** = 7+2×3（3 事务同连接、每笔请求+响应各 1 段）；21 按实际分段数校准（最小 = 3+3+4 = 10：请求 1 段 + 响应跨 ≥2 段）；24 = **18** = 9+9（两会话各单事务，第二会话握手包号 = 10 = 前会话 9+1）。实现期以实际输出校准，若引擎 ACK 合并/分段与约定不符须同步四件套。）

## 3. 线上编码和偏移断言

层链 `[tcp, http, doh]`，无 VLAN/IP options/TCP options 时 HTTP 起行 IPv4 offset 54、IPv6 offset 74。**DNS wire 在 HTTP body 内，偏移不固定**：body 起点 = 54/74 + 该 fixture 固定 HTTP 头集合字节长（头集合由配置钉死，偏移可预算）。断言分层：

1. **HTTP 起行与头（fields 权威断言）**：请求帧 offset 54 起为 ASCII（POST：`50 4F 53 54 20 2F 64 6E 73 2D 71 75 65 72 79 20`（`POST /dns-query `）；GET：`47 45 54 20 2F 64 6E 73 2D 71 75 65 72 79 3F 64 6E 73 3D`（`GET /dns-query?dns=`））。字段断言用 `http.request.method`/`http.request.uri`/`http.request.uri.path`/`http.content_type`/`http.content_length`/`http.accept`/`http.host`；GET 的 query 用 `http.request.uri.query.parameter`（实测名含 `dns=<b64>`）。
2. **DNS wire（`http.file_data` + 自动内层 `dns.*` 双通道）**：`http.file_data` nonzero 证明 body 存在；响应帧（2xx + `Content-Type: application/dns-message`）**自动内层解码**，`dns.id`/`dns.qry.name`/`dns.qry.type`/`dns.qry.class`/`dns.count.queries`/`dns.count.answers` 实测可见（tshark 3.6.14 实证）；POST 请求 body 同样自动内层解码。DNS 头 12B 的十六进制常量用 frames 断言：`ID` 两字节按 fixture、`flags` 请求 `01 00`（RD）+ 响应 `81 80`（QR|RD|RA|RCODE=0）、`QDCOUNT=00 01`。GET 请求帧无 `dns.*`（实测），其 wire 内容断言 = query 参数 base64url 文本（`http.request.uri.query.parameter` 含 `dns=`）+ 解码后与响应 Question 一致的帧间关系（响应 `dns.qry.name` 与请求 base64 解码名一致，通过 fixture 固定名断言）。
3. **TCP 分段与重组**：分段边界不是 HTTP/DNS 边界（RFC 7230 §3.3.2）——跨段时先按 `tcp.stream` 重组，再对重组后末帧断言完整 HTTP+DNS（`http.content_length`=body 实际长、`dns.count.answers` 与配置一致）。
4. **has_payload 语义**：权威断言是 `http.file_data` nonzero + 响应帧 `dns.*` 字段非空 + frames hex；`frame.len>80` 只作宽松代理，不得以包数/PSH 标志替代。
5. **多会话包号规则**：`sessions[]` 按多会话展开整块回放，第二会话 TCP 握手包号 = 前一会话总包数 + 1；断言跨会话关联用 `tcp.stream` 区分，不硬编码全局包号。

## 4. 正例逐项断言契约

约定 packet_count 见 §2 表；以下 fields/frames 为最低断言集，实现期可增不可减。默认 fixture 地址 `192.0.2.66 → 198.51.100.66`、`dst_port=80`；查询 `www.example.com`（wire QNAME 编码长 17B = 15 展示字符 + 2，wire 33B，见设计 §3.5）；响应 A 记录 `192.0.2.1` TTL=300（wire 64B）。`same_as_packet` 指与请求帧同 `tcp.stream` 对侧帧的字段值相同——实现期以 case JSON 支持的断言语义落地。

1. **`doh_post_ipv4_http11`**（9）：断言握手（`tcp.flags.syn`/`syn_ack`/`ack` 各一）、第 4 帧 `http.request.method=POST`、`http.request.uri.path=/dns-query`、`http.content_type=application/dns-message`、`http.content_length` nonzero（**精确值 33 由用例 16 专断，此处不断言精确值**——M8 修复，消除原子性重叠）、`http.accept=application/dns-message`、请求帧 `http.file_data` nonzero + 帧 4 `dns.id`/`dns.qry.name=www.example.com`（自动解码）；帧 5 `http.response.code=200`、`http.content_type=application/dns-message`、`http.content_length` nonzero、`dns.id` 与请求 same_as、`dns.flags.response=1`、`dns.flags.rcode=0`、`dns.count.answers=1`；挥手（帧 6–9，FIN|ACK→ACK→FIN|ACK→ACK）。
2. **`doh_get_ipv4_base64url`**（9）：握手；第 4 帧 `http.request.method=GET`、`http.request.uri` 以 `/dns-query?dns=` 开头、`http.request.uri.query.parameter` 恰一个 `dns=<b64>`、b64 不含标准 base64 字母表字符（`+`/`/`）与 padding `=`（含 `-`/`_` 时按 base64url 字母表），`http.content_length=0`（本版固定形态，设计 §3.1）、无 `http.file_data`；帧 5 响应 `dns.qry.name=www.example.com` 与请求 fixture 名一致、`dns.id` 与 base64 解码 ID 一致（解码由实现侧校验，断言用 fixture 固定 ID）；挥手。
3. **`doh_post_ipv6_http11`**（9）：`ipv6.nxt=6`、HTTP 起行 offset 74、POST 形状与用例 1 断言同；请求/响应 `http.content_type`、`http.content_length`、`dns.qry.name`、`dns.id` same_as 同用例 1；**不得**出现 `ip.version=4` 地址。
4. **`doh_get_ipv6_base64url`**（9）：IPv6 独立 fixture（`2001:db8::66 → 2001:db8::100:66`，显式给出，不从 IPv4 推导）；断言同用例 2（偏移 74、query 参数无 padding、响应 Question 一致）。
5. **`doh_dns_header_query`**（9）：**13 项头字段逐字段全覆盖（M1 修复；按 tshark 3.6.14 实测发射帧分布）**——请求帧（发射 QR/Opcode/TC/RD/Z 与 4 个 COUNT）：`dns.id` nonzero（fixture ID 固定时精确断言）、`dns.flags.response=0`、`dns.flags.opcode=0`、`dns.flags.truncated=0`（TC）、`dns.flags.recdesired=1`（RD）、`dns.flags.z=0`（Z 保留位）、`dns.count.queries=1`（QDCOUNT）、`dns.count.answers=0`（ANCOUNT）、`dns.count.auth_rr=0`（NSCOUNT，**单数字段**）、`dns.count.add_rr=0`（ARCOUNT，**单数字段**）；响应帧（tshark 仅在响应帧发射 AA）：`dns.flags.authoritative=0`（AA）、`dns.flags.truncated=0`、`dns.flags.z=0`、`dns.count.auth_rr=0`、`dns.count.add_rr=0`；frames：offset 0–1 ID 两字节、flags 两字节 `01 00`（QR=0|Opcode=0|TC=0|RD=1，AA/RA/Z/RCODE 位均为 0）、QDCOUNT `00 01`、ANCOUNT/NSCOUNT/ARCOUNT `00 00 00 00 00 00`——AA/TC/Z/NSCOUNT/ARCOUNT 至此全部有显式断言，不留零测试字段。
6. **`doh_dns_question_a`**（9）：`dns.qry.name=www.example.com`、`dns.qry.name.len=15`（**tshark 实测为展示字符串长度，非 wire 编码长度**；wire QNAME 编码长 17，见设计 §3.5）、`dns.qry.type=1`（A）、`dns.qry.class=1`（IN）；frames：QNAME 前 3 字节 `03 77 77 77`（`3www` 长度前缀）、根标签 `00` 后接 QTYPE `00 01`、QCLASS `00 01`（大端）。
7. **`doh_dns_question_aaaa`**（9）：`dns.qry.type=28`；响应 `dns.resp.type=28`、`dns.aaaa` 为配置 IPv6 答案（如 `2001:db8::1`）。
8. **`doh_dns_question_https`**（9）：`dns.qry.type=65`（HTTPS/SVCB，RFC 9460）；响应 `dns.resp.type=65`。
9. **`doh_dns_question_root`**（9）：请求 QNAME 仅零字节根标签——实测 tshark 显示 `dns.qry.name=<Root>`、`dns.qry.name.len=6`（展示形式）、`dns.count.labels=1`（**C2 修复：实测 tshark 3.6.14 将根标签计为 1 个 label，非 0**）；wire 长 17B（12 头 + 1 根标签 + 4），权威断言 `http.content_length=17` + frames（QNAME 首字节 `00`）。
10. **`doh_dns_response_noerror`**（9）：响应 `dns.flags.response=1`、`dns.flags.opcode=0`、`dns.flags.recavail=1`（RA）、`dns.flags.rcode=0`、`dns.id` same_as 请求、`dns.count.queries=1`、`dns.count.answers=1`。
11. **`doh_dns_response_nxdomain`**（9）：响应 `http.response.code=200`（HTTP 200 ≠ DNS 成功，RFC 8484 §4.2.1）、`dns.flags.rcode=3`、`dns.count.answers=0`；请求 Question 正常。
12. **`doh_dns_response_servfail`**（9）：`http.response.code=200`、`dns.flags.rcode=2`、`dns.count.answers=0`。
13. **`doh_dns_answer_ttl`**（9）：A 答案结构：`dns.count.answers=1`、`dns.resp.type=1`、`dns.resp.class=1`、`dns.resp.ttl=300`、`dns.a=192.0.2.1`；frames：答案 NAME 前缀 `03 77 77 77`、TYPE `00 01`、CLASS `00 01`、TTL 4B 大端 `00 00 01 2C`（300）、RDLENGTH `00 04`、RDATA `C0 00 02 01`（192.0.2.1）。
14. **`doh_dns_ttl_boundary`**（18 = 9+9，两变体分别建流）：变体 A `ttl=0`：`dns.resp.ttl=0`、`http.cache_control` 含 `max-age=0`；变体 B `ttl=4294967295`（0xFFFFFFFF）：`dns.resp.ttl=4294967295`、`http.cache_control` 含 `max-age=4294967295`（tshark 3.6.14 实测可解析满值）。
15. **`doh_http_keepalive_multi_transaction`**（13 = 7+2×3）：单 `tcp.stream` 承载 ≥3 笔查询（A→AAAA→HTTPS，QNAME 各异或同、ID 递增 distinct）；断言请求/响应**严格交替**（`http.request` 与 `http.response` 帧序 1:1，无 pipelining，RFC 7230 §6.3.1）、**逐请求 Connection 策略（H2 修复，设计 §5 钉死）：每笔请求均显式携带 `Connection: keep-alive`，仅末笔按 close/keep-alive 配置决定（默认 close，末笔后挥手）**——不再断言"只有首请求带 keep-alive"（无设计依据，已废弃）、每笔响应 `dns.id` same_as 对应请求、`dns.count.answers` 按各自响应、末响应后挥手；HTTP/1.1 无 stream 概念（多流不适用，设计 §4 声明）。
16. **`doh_http_content_length_exact`**（9）：`http.content_length_header` 恰为 `33`（十进制 ASCII）、`http.content_length=33`、响应 `http.content_length=64`；frames 断言 header 行 ASCII `43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 33 33`（`Content-Length: 33`）。**33/64 精确值仅本用例专断**（用例 1/2 只断言 nonzero——M8 修复）。
17. **`doh_http_cache_control`**（9）：响应 `http.cache_control` 含 `max-age=300` 恰等于答案最小 TTL（RFC 8484 §5.1）；TTL 300 唯一时相等，多答案取最小（断言值 = 配置的最小 TTL）。
18. **`doh_http_error_400`**（9）：GET 请求 URI 无 `dns` 参数（如 `/dns-query`），**响应 400 经 `response.status: 400` 非 2xx 通道声明（设计 §6，H1 修复）**；响应 `http.response.code=400`、**无 `http.file_data`**、`http.content_length=0`、无 DNS wire（非 2xx 自动应答确定性规则：空 body、无 DNS wire，设计 §3.1/§5）；不出现 `dns.*` 响应字段。
19. **`doh_http_error_404`**（9）：GET `/unknown-path`（响应 404 经 `response.status: 404` 通道声明）；响应 `http.response.code=404`、空 body、无 `dns.*`。
20. **`doh_http_error_415`**（9）：POST 请求 `Content-Type: text/plain`（HTTP 语义上服务器返回 415 的形状由配置声明，响应经 `response.status: 415` 通道）；响应 `http.response.code=415`、空 body、无 `dns.*`（§4.2.1 415 属"换服务器重试"建议的合法错误形态，本版仅断言响应形态）。
21. **`doh_mss_large_response`**（≥10 校准，最小 = 3+3+4 = 10：请求 1 段 + 响应跨 ≥2 段）：响应多 Answer（如 20 条 A 记录或长 TXT），MSS 压小使响应跨 ≥2 个 TCP 分段；断言 `tcp.len` 分布、重组后末帧 `http.content_length`=body 实际长、`dns.count.answers` 与配置一致、`http.file_data` 完整（frames 尾字节=最后 RDATA 对应 hex）。
22. **`doh_dns_qname_max`**（18 = 9+9，两变体分别建流）：变体 A 单标签 63 字节（实测 `dns.qry.name.len=63`、`http.content_length=12+65+4=81`——**63 标签 wire QNAME 编码 = 1 长度前缀 + 63 字符 + 1 根标签 = 65B**）；变体 B 全名 255 字节（4 标签 63/63/63/61，wire QNAME 编码 255B）——**权威断言 `http.content_length=271`（12 头 + 255 QNAME + 4）**；实测 tshark `dns.qry.name.len` 显示为 253（展示长度口径），实现期若字段值与此处记录不一致以 `http.content_length` + frames 长度前缀字节为准，并同步四件套。
23. **`doh_dns_id_boundary`**（18 = 9+9，两变体分别建流）：变体 A `dns_id=0`：请求/响应 `dns.id=0` same_as；变体 B `dns_id=65535`：`dns.id=65535` same_as（RFC 1035 §4.1.1 未保留值，合法）。**与 SHOULD 的关系（M6 修复）**：RFC 8484 §4.1 建议 DoH 客户端 DNS ID=0（SHOULD，缓存友好）；本版允许配置/随机以便测关联，属有意偏离（设计 §3.2/§5 声明）——变体 A 恰为该 SHOULD 推荐值，变体 B 及其他用例的随机/递增 ID 均为该偏离的显式测试形态。
24. **`doh_multi_session`**（18 = 9+9）：会话 1（`src_port=42066`，A 查询）+ 会话 2（`src_port=42067`，AAAA 查询）不同源端口；断言两 `tcp.stream` distinct、各自 DNS ID 独立（distinct_values 两会话各一，相同范围但不相等即可，fixture 固定时精确断言）、**第二会话握手包号 = 10（多会话展开起点 = 前会话总包数 9 + 1）**、每会话响应 Question 匹配本会话请求（无串用）。

## 5. 负例契约

负例必须在 planner/validator 失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP/HTTP 外壳的假成功；执行期 `expect` 严格只有 `expect_error`、`error_contains`。锚词与设计 §7 表一一对应：

| ID | `wire_fault` 注入口（H5，与设计 §6/§7 同枚举） | 故障输入 | 目标 `error_contains` |
|---|---|---|---|
| `doh_neg_query_missing` | `query_missing` | GET 配置缺 `dns` 参数（URI 无 query） | `dns`、`query` 或 `parameter` |
| `doh_neg_base64_invalid` | `base64` | base64url 含非法字符（标准 base64 字母表字符 `+`/`/`、padding `=` 或非字母表字节） | `base64`、`url` 或 `decode` |
| `doh_neg_base64_padding` | `padding` | base64url 带 `=` padding | `base64`、`padding` 或 `url` |
| `doh_neg_base64_truncated` | `b64_short` | **base64url 解码产出 <12B**（解码链，设计 §3.4） | `decode`、`truncate` 或 `length` |
| `doh_neg_dns_header_short` | `dns_header_short` | **POST body 原始字节 <12B**（不经 base64 解码链） | `dns`、`header` 或 `length` |
| `doh_neg_dns_qdcount_zero` | `qdcount` | QDCOUNT=0（本版 validator 设计决策） | `question`、`qdcount` 或 `dns` |
| `doh_neg_dns_qname_overflow` | `qname` | QNAME>255 或单标签>63 | `qname`、`label` 或 `length` |
| `doh_neg_dns_question_truncated` | `question_truncated` | Question 缺零标签终止/QTYPE/QCLASS 截断 | `question`、`wire` 或 `length` |
| `doh_neg_content_type` | `content_type` | Content-Type 非 application/dns-message | `content-type`、`media` 或 `type` |
| `doh_neg_method` | `method` | 方法非 POST/GET | `method` 或 `http` |
| `doh_neg_content_length` | `content_length` | Content-Length≠DNS body 字节 / **body 缺失或多出（并入原 `body_missing` 分支，锚词含 `body`/`dns`）** | `content-length`、`length`、`body` 或 `dns` |
| `doh_neg_carrier_port` | `carrier` | 层链缺 http（tcp→doh）、端口/载体矛盾 | `carrier`、`port` 或 `layer` |
| `doh_neg_response_id` | `response_id` | 响应 DNS ID≠请求 ID | `id`、`match` 或 `correlation` |
| `doh_neg_response_question` | `response_question` | 响应 Question 与请求错配（QNAME/QTYPE/QCLASS）/ **2xx 无 DNS 体（并入原 `http200_no_dns` 分支，锚词含 `body`/`wire`）** | `question`、`match`、`correlation`、`body` 或 `wire` |

**合并说明（C4 修复）**：`body_missing` 与 `http200_no_dns` 两个分支不设独立行/ID（设计 §7 后注同口径）——POST 无 body 由 `content_length` 校验覆盖、2xx 无 DNS 体由 `response_question` 校验覆盖，锚词已并入目标行；本表 14 行与设计 §7 表、§9 ID 表三方一一对应、同序。

合法协议事件不进负例（防误报）：HTTP 400/404/415 错误响应本身、DNS NXDOMAIN/SERVFAIL RCODE、TTL=0/满值、Cache-Control 缺失（§5.1 SHOULD）、DNS ID 0/满值、根 QNAME、GET 与 POST 并存。

## 6. 五层覆盖映射

| 层面 | 用例 ID | 说明 |
|---|---|---|
| 功能 | 1–13、15–20、22–24（正）；25–38（负） | GET/POST 两映射、DNS 头 12B 逐字段、Question A/AAAA/HTTPS/根、Answer 结构、RCODE 值域、缓存头、错误响应形态全正例；错误分支逐类负例（§7 每行对应 ≥1 条） |
| 性能 | 21、22 | 大响应跨 MSS 分段重组（21）+ QNAME 255/单标签 63 上界（22）；**DNS wire 上界 65535 由实现校验（validator 对超限配置报错），测试侧不构造完整 65535B 单消息，用 QNAME 255 上界 + MSS 大响应分段代理覆盖（与设计 §8 同口径声明，M2 修复）**；发包速率由框架既有配置承载（v1.1 §10 口径） |
| 数据场景 | 5、6、14、23；负 27、31 | DNS 字段值域与编码变体：ID 0/满值、TTL 0/满值、QNAME 最长/根名、base64url 无填充/非法/padding、QDCOUNT 边界拒绝 |
| 地址与流 | 1（v4 单流基线）、3（v6）、4（v6 GET）、24（多会话双四元组） | v4+v6 必覆盖；流关联显式不适用（纯查询无派生流，设计 §4 声明）；多流不适用（HTTP/1.1 无 stream，设计 §4 声明） |
| 业务 | 1（解析器 A 查询）、7/8（AAAA/HTTPS 记录）、14/17（缓存策略）、15（长连接多查询）、16（POST 变体）、3/4（IPv6 解析） | 现网 DoH 解析器典型场景优先 |

## 7. 机器契约与静态检查

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/doh.json` 通过；当前数组恰含 1 条 `doh_neg_unregistered`：`proto=doh`、层链 `[{"tcp":{}},{"http":{}},{"doh":{}}]`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。
2. 实现注册 `doh` 层后：移除占位，按 §2 顺序补入 38 个语义用例；ID、顺序与设计 §9 完全一致（脚本核验）。
3. 正例每条含 `packet_count`（或 `min_packets`）+ `fields` + `frames`；`fields` 只用 §1 实测存在的 tshark 字段，不伪造 `doh.*`；DNS 断言走 `http.file_data` + 自动内层 `dns.*` 双通道；GET 请求侧 DNS 用 `http.request.uri.query.parameter` + frames hex。`packet_count` 按 §1 统一公式 3+N+4（单事务 9；多事务 7+2M；多会话求和），断言帧位按约定（请求 = 握手后第 1 帧、响应 = 下一帧、挥手 = 末 4 帧）。
4. 负例 `expect` 键集合恰为 `{expect_error, error_contains}`，不加 packet_count/fields。
5. 断言包号引用跨会话/跨连接时用 `tcp.stream`+会话起点规则（§3.5），不硬编码全局包号；动态值用 `same_as_packet`/`distinct_values`/`nonzero`。
6. GET 请求帧不得臆造 `dns.*` 字段（3.6.14 默认不自动解码 URI query）；若实现期改用 `-d` 强制解码，四件套同步更新。

## 8. 三方一致性表

设计 §9、本文 §2、实现后 `doh.json` 保持同一 38 个语义 ID、同一顺序（当前 JSON 另有占位，不计入）：

```text
doh_post_ipv4_http11
doh_get_ipv4_base64url
doh_post_ipv6_http11
doh_get_ipv6_base64url
doh_dns_header_query
doh_dns_question_a
doh_dns_question_aaaa
doh_dns_question_https
doh_dns_question_root
doh_dns_response_noerror
doh_dns_response_nxdomain
doh_dns_response_servfail
doh_dns_answer_ttl
doh_dns_ttl_boundary
doh_http_keepalive_multi_transaction
doh_http_content_length_exact
doh_http_cache_control
doh_http_error_400
doh_http_error_404
doh_http_error_415
doh_mss_large_response
doh_dns_qname_max
doh_dns_id_boundary
doh_multi_session
doh_neg_query_missing
doh_neg_base64_invalid
doh_neg_base64_padding
doh_neg_base64_truncated
doh_neg_dns_header_short
doh_neg_dns_qdcount_zero
doh_neg_dns_qname_overflow
doh_neg_dns_question_truncated
doh_neg_content_type
doh_neg_method
doh_neg_content_length
doh_neg_carrier_port
doh_neg_response_id
doh_neg_response_question
```

## 9. 修订记录

- v1.0.0（2026-08-20）：旧稿首版（与旧设计稿配套的 14+6 ID 索引）。
- v2.0.0（2026-08-31）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写/review，取代 2026-08-20 旧稿（旧稿见 git 历史）。索引表改为需求五列格式（覆盖列引用设计 § 编号）；以 tshark 3.6.14 构造 pcap 实测固化断言基线——HTTP/1.1 明文 `application/dns-message` 的 2xx 响应与 POST 请求 body **自动内层解码 DNS**（`dns.id`/`dns.qry.name`/`dns.qry.type`/`dns.qry.class`/`dns.count.*`/`dns.resp.ttl`/`dns.a`/`dns.flags.rcode` 实证），GET 请求 URI query 默认不自动解码（走 `http.request.uri.query.parameter` + frames hex）；用例按原子原则重排为 38 条（24 正 + 14 负），新增 DNS 头逐字段/Question 分类型/边界/缓存/错误响应/多事务/MSS/多会话用例，删除 http2/3/TLS/pcap_nic/多流（本版边界，见设计 §1）；新增 §3 偏移与 dual-channel 断言、§6 五层映射、§8 三方一致性表。状态：**待独立隔离审查**。
- v2.0.1（2026-08-31）：按独立对抗审查 24 项问题清单修复（4C/5H/9M/6L），状态改为"修复完成，待原审查员复验关闭"。关键修复：①【C1】§1 字段清单与用例 5：`dns.count.auth_rrs`/`add_rrs` 改单数 `dns.count.auth_rr`/`add_rr`（`tshark -G fields` 实证只有单数）；②【C2】用例 9 根名断言 `dns.count.labels=0` 改 `=1`（实测 tshark 把根标签计为 1）；③【H3】packet_count 公式统一为 3+N+4（N=分段数）：单事务 8→**9**（旧"8=3+1+4"漏计响应分段）、用例 15 = 3+2N+4 → **13 = 7+2×3**、双流用例 14/22/23 = 9+9=**18**、用例 24 = **18**（第二会话握手包号 9→10）——以引擎 teardown 4 帧 + 同引擎 hls/http_flv 已实现用例实测（9/11/13/15 等差 2）为据；④【M1】用例 5 补 AA/TC/Z/NSCOUNT/ARCOUNT 断言（按 tshark 发射帧分布：TC/Z/COUNT 落请求帧、AA 落响应帧）；⑤【H2】用例 15 断言改"每笔请求均带 keep-alive、末笔按配置"（设计 §5 钉死策略）；⑥【H1】用例 18/19/20 与 `response.status` 非 2xx 通道对齐；⑦【M6】用例 23 标注 RFC 8484 §4.1 ID=0 SHOULD 与有意偏离；⑧【M8】用例 1 的 `http.content_length=33` 改 nonzero（精确值归用例 16 专断）；⑨【H5】§5 表补 `wire_fault` 注入口列（14 值与设计 §6/§7 枚举一一对应）；⑩【C4】§5 表并入 body_missing/http200_no_dns 分支锚词，14 行与设计 §7/§9 三方同序；⑪【M2】§6 与设计 §8 同步声明 65535 上界由实现校验、测试用 QNAME 255+MSS 分段代理；⑫【L6】§1 挥手 4 帧旁注"实现期校准值，非 RFC 消息数"；⑬用例 22 变体 A 长度修正 80→**81**（12+65+4，实测 http.content_length=81；含长度前缀与根标签）并按两变体建流改 18；⑭ §1 字段清单补 `dns.flags.authoritative`/`truncated`/`z`/`dns.count.labels`。