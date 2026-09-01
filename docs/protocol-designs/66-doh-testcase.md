# DOH（DNS over HTTPS / RFC 8484）测试用例契约

> 版本：v3.0.2（测试用例，v1.3 行为面全枚举重出 + 复验修复轮）
> 日期：2026-08-31
> 配套设计：`docs/protocol-designs/66-doh-design.md`（v2.2.0）
> 机器契约：`trafficgen/test/protocol_pcap/cases/doh.json`（proto key：`doh`；本版不写文件，当前 JSON 仅含注册前置占位；占位 dst_port 已对齐主 profile 明文端口 80）
> 状态：**v1.1 隔离审查已 clean**（v2.0.1）；现按《需求文档 v1.3》完成行为面全枚举重出（rr-doh 审查清单全落地），**待复验**。
> 修订记录：v3.0.2（2026-09-01）：复验修复轮（N1-N12 逐项落地、删重复例 #85、§6 改 ID 引用，110 条）。v3.0.1（2026-09-01）：rr-doh 全清单对账 78→111 条。v3.0.0（2026-09-01）：行为面全枚举重出 38→78 条。v2.0.1（2026-08-31）：按独立对抗审查 24 项清单修复（4C/5H/9M/6L），关键项：`dns.count.auth_rr`/`add_rr` 单数化、根名 labels=1、packet_count 公式统一（8→9、多事务 13、双流 18）、用例 5 补 AA/TC/Z/NSCOUNT/ARCOUNT 断言、用例 1 精确长度改 nonzero、用例 15 改逐请求 keep-alive 断言、§5 表补 wire_fault 列（详见 §9）。v2.0.0（2026-08-31）：按《协议设计文档与用例文档需求文档 v1.1》独立隔离审查流程重写/review，取代 2026-08-20 旧稿（旧稿见 git 历史）。

## 1. 测试原则和未注册边界

用例按《需求文档 v1.3》从**可测试行为面全枚举**派生（消息 × 字段 × 值域 × 边界相邻值 × 错误分支 × 载体 × 场景 × 交互，独立审查员 rr-doh 枚举约 135 点），共 **110 个唯一语义 ID：84 正例 + 26 负例**。**不与设计章节一对一映射**（v1.2 废除）：设计一条规格可派生多条用例，数量由行为面决定；每条用例「依据」列标注规范章节（RFC 优先）与设计 §。**一个用例只验证一个可独立判定真伪的行为点**（原子不可再分判定标准：删除该用例后至少一个独立分支失去直接证据）；`expect_error` 用例不混入成功结构断言。**输出契约**：pcap 文件输出与 `port_group`/NIC 网口输出共用本契约、断言一致（需求 v1.3 §8.2-7）。

当前 JSON 只保留一个 `doh_neg_unregistered` 注册前置占位：`proto=doh`、`expect_error=true`、`error_contains` 精确为 `unknown layer`；该占位不计入语义 ID，不得把拒绝、0 包或空 PCAP 报告为 DOH 行为通过。**设计行/未来规划/待实现边界不得写入当前 JSON ID 集合**（需求 v1.3 §1 三件套纪律）；注册后移除占位，按本文 §2 全量补入 110 个语义用例。

**TSHARK 实测基线（本机 3.6.14，构造 pcap 实证，非臆造）**：HTTP/1.1 明文响应 `Content-Type: application/dns-message` 且 2xx 时，tshark **自动对该 HTTP body 内层解码为 DNS**——`dns.id`、`dns.flags.response`、`dns.flags.rcode`、`dns.qry.name`、`dns.qry.type`、`dns.qry.class`、`dns.count.queries`、`dns.count.answers`、`dns.resp.ttl`、`dns.resp.type`、`dns.resp.class`、`dns.a` 均实测可见（样本：POST+GET 各一完整流，DNS 查询 `www.example.com A IN`、响应 A 记录 TTL=300）。**请求侧**（POST body 或 GET URI 参数）：POST body 同样自动内层解码（`dns.id`/`dns.qry.name` 实测可见）；**GET 请求的 URI query 解码**在 3.6.14 默认**不**自动进行（实测仅帧对 DNS 的 `dns.id` 出现在响应帧），GET 侧 DNS 断言走 `http.request.uri.query.parameter` 的 base64url 文本 + frames hex 的 body 起点偏移断言，**不臆造 GET 请求帧有 `dns.*` 字段**（解码支持可由 `-d` 强制，case JSON 实现时定并同步四件套）。响应帧 `dns.*` 断言权威。

**可用断言字段**（`tshark -G fields` 已核验，与设计 §3 一致）：`http.request.method`、`http.request.uri`、`http.request.uri.path`、`http.request.uri.query`、`http.request.uri.query.parameter`、`http.request.line`、`http.content_type`、`http.content_length_header`、`http.content_length`、`http.file_data`（FT_STRING，body 原始字节）、`http.response.code`、`http.response.line`、`http.cache_control`、`http.host`、`http.accept`、`dns.id`、`dns.flags.response`、`dns.flags.opcode`、`dns.flags.rcode`、`dns.flags.authoritative`、`dns.flags.truncated`、`dns.flags.recdesired`、`dns.flags.recavail`、`dns.flags.z`、`dns.count.queries`、`dns.count.answers`、`dns.count.auth_rr`、`dns.count.add_rr`、`dns.count.labels`、`dns.qry.name`、`dns.qry.type`、`dns.qry.class`、`dns.qry.name.len`、`dns.resp.ttl`、`dns.resp.type`、`dns.resp.class`、`dns.a`、`dns.aaaa`、`tcp.stream`、`tcp.len`、`tcp.dstport`、`tcp.flags.*`、`ip.version`、`ipv6.nxt`。无 `doh.*` 专用字段，不臆造。**单数字段实测声明（C1 修复）**：本机 tshark 3.6.14 的 `tshark -G fields` 只有单数 `dns.count.auth_rr`/`dns.count.add_rr`，**不存在** `dns.count.auth_rrs`/`dns.count.add_rrs` 复数形式。**发射帧分布实测（M1 修复依据）**：查询帧发射 `dns.flags.response/opcode/truncated/recdesired/z` 与 4 个 COUNT；`dns.flags.authoritative/recavail/rcode` 仅**响应帧**发射；**TC/Z 在响应帧同样发射**（实测）——AA/RA/RCODE 断言落响应帧、TC/Z 断言双侧、其余落请求帧（用例 5 据此分布，断言集为安全超集）。

**动态字段禁止硬编码**：DNS ID、随机查询名、随机端口用 `nonzero`、`distinct_values`、`same_as_packet`；QNAME 主体、QTYPE、QCLASS、TTL、RCODE、答案内容为预配置值，允许 fixture 显式给出。DNS wire 不动的内容断言用 `http.file_data` 存在性与 frames hex 前缀；DNS 头/Question 字段断言用 `dns.*` 实测字段（自动内层解码），两次互为印证。**实测字段语义注意**：`dns.qry.name.len` 在 tshark 3.6.14 为**展示字符串长度**（`www.example.com` 显示 15）、`dns.qry.name` 根名显示 `<Root>`、255 上限名显示 253——编码/长度类断言一律以 `http.content_length`（body 真实字节长）与 frames 长度前缀字节为权威，`dns.qry.name.len` 仅作辅助（§4 用例 6/9/22）。

**包数约定（H3 统一，设计 §9 完成定义同口径）**：每连接包数 = **3（握手 SYN/SYN-ACK/ACK）+ N（承载 HTTP 消息的 TCP 分段数，请求与响应分段之和）+ 4（挥手：本引擎 teardown 序列 FIN|ACK→ACK→FIN|ACK→ACK 共 4 帧——实现期校准值，非 RFC 消息数）**。**单事务**：请求+响应各 1 段时 N=2 → **9**（3+2+4）；旧约定表"8 = 3+1+4"漏计响应分段（假设请求/响应合并单段或存在一笔裸 ACK，与引擎实测不符——引擎数据段与挥手间无独立 ACK 帧），v2.0.1 起废弃。**多事务 keep-alive 同连接**：M 笔事务每笔各 1 段 → N=2M → **7 + 2M**（M=3 → 13；与 §2 旧公式 3+2N+4 在 N=事务数时等价，本版统一表述为 3+N+4 / 7+2M）。**实证**：同引擎 `http` 层已实现用例（`hls.json`/`http_flv.json`）packet_count 实测——单事务 9、2 事务 11、3 事务 13、4 事务 15，等差 2，与公式一致（请求帧 = 包 4、响应帧 = 包 5、挥手 = 包 6–9）。**多会话** = 各会话之和，第二会话起点 = 前会话总包数 + 1（设计 §5 多会话展开）。约定数字是实现基线，实现采用不同 ACK 合并/分段方式时须同步更新四件套，不得把约定数字当 RFC 消息数。

## 2. 原子用例索引

| # | ID | 类型 | 载体 | 覆盖（一句话） | 依据 | 包数 |
|---:|---|---|---|---|---|---:|
| 1 | `doh_post_ipv4_http11` | 正 | TCP/IPv4 | POST/IPv4 明文单流基线（Content-Type/Length/Accept、DNS wire 在 body、ID same_as） | RFC 8484 §4.2.2/§6+设计§3.1 | 9 |
| 2 | `doh_get_ipv4_base64url` | 正 | TCP/IPv4 | GET `dns` 参数 base64url 无 padding（无 body、CL:0 本版固定形态） | RFC 8484 §4.1/§6+RFC 7230 §3.3.2+设计§3.4 | 9 |
| 3 | `doh_post_ipv6_http11` | 正 | TCP/IPv6 | POST/IPv6（ipv6.nxt=6、offset 74） | RFC 8484 §4+设计§2 | 9 |
| 4 | `doh_get_ipv6_base64url` | 正 | TCP/IPv6 | GET/IPv6 独立 fixture（2001:db8::66 → 2001:db8::100:66） | RFC 8484 §4.1+设计§2 | 9 |
| 5 | `doh_dns_header_query` | 正 | TCP/IPv4 | DNS 头 12B 大端逐字段 13 项（按 tshark 发射帧分布） | RFC 1035 §4.1.1+设计§3.2 | 9 |
| 6 | `doh_dns_question_a` | 正 | TCP/IPv4 | QNAME 标签编码、QTYPE=A(1)、QCLASS=IN(1) | RFC 1035 §3.1/§4.1.2+设计§3.3 | 9 |
| 7 | `doh_dns_question_aaaa` | 正 | TCP/IPv4 | QTYPE=AAAA(28) | RFC 1035 §3.2.2+设计§3.3 | 9 |
| 8 | `doh_dns_question_https` | 正 | TCP/IPv4 | QTYPE=HTTPS(65) | RFC 9460+设计§3.3 | 9 |
| 9 | `doh_dns_question_root` | 正 | TCP/IPv4 | 根 QNAME 最短消息（wire 17B） | RFC 1035 §3.1+设计§3.3 | 9 |
| 10 | `doh_dns_response_noerror` | 正 | TCP/IPv4 | RCODE=0、QR=1、RA=1、ID same_as | RFC 1035 §4.1.1+RFC 8484 §4.2.1+设计§5 | 9 |
| 11 | `doh_dns_response_nxdomain` | 正 | TCP/IPv4 | RCODE=3、ANCOUNT=0、HTTP 200（HTTP 成功 ≠ DNS 成功） | RFC 8484 §4.2.1+设计§4③ | 9 |
| 12 | `doh_dns_response_servfail` | 正 | TCP/IPv4 | RCODE=2、ANCOUNT=0、HTTP 200 | RFC 8484 §4.2.1+设计§4③ | 9 |
| 13 | `doh_dns_answer_ttl` | 正 | TCP/IPv4 | A 答案结构 NAME/TYPE/CLASS/TTL/RDLENGTH/RDATA | RFC 1035 §4.1.3+设计§3.3 | 9 |
| 14 | `doh_http_keepalive_multi_transaction` | 正 | TCP/IPv4 | 同连接 3 事务严格配对、逐请求 keep-alive 策略 | RFC 7230 §6.3/§6.3.2+设计§5 | 13 |
| 15 | `doh_http_content_length_exact` | 正 | TCP/IPv4 | Content-Length 精确 33/64 | RFC 7230 §3.3.2+设计§3.5 | 9 |
| 16 | `doh_http_cache_control` | 正 | TCP/IPv4 | max-age=答案最小 TTL | RFC 8484 §5.1+设计§3.6 | 9 |
| 17 | `doh_http_error_400` | 正 | TCP/IPv4 | GET 缺 dns 参数→400 空 body 无 DNS wire | RFC 7231 §6.5.1+RFC 8484 §4.2.1+设计§3.1 | 9 |
| 18 | `doh_http_error_404` | 正 | TCP/IPv4 | 未知 URI→404 空 body | RFC 7231 §6.5.4+RFC 8484 §4.2.1+设计§3.1 | 9 |
| 19 | `doh_http_error_415` | 正 | TCP/IPv4 | 媒体类型不支持→415 空 body | RFC 7231 §6.5.13+RFC 8484 §4.2.1+设计§3.1 | 9 |
| 20 | `doh_mss_large_response` | 正 | TCP/IPv4 | 大响应跨 MSS 分段重组 | RFC 7230 §3.3.2+设计§8 | 校准≥10 |
| 21 | `doh_multi_session` | 正 | TCP/IPv4 | 多会话展开双四元组、状态不串用 | 设计§5/§8 | 18 |
| 22 | `doh_port_nondefault_post` | 正 | TCP/IPv4 | 非默认端口 8080 POST（全栈语义同基线） | 设计§2 端口变体声明 | 9 |
| 23 | `doh_port_nondefault_get` | 正 | TCP/IPv4 | 非默认端口 8080 GET | 设计§2 端口变体声明 | 9 |
| 24 | `doh_concurrent_sessions` | 正 | TCP/IPv4×2 | 并发会话：双客户端四元组交错（concurrent: true），状态不串用 | 设计§6 翻案+§5 | 18 |
| 25 | `doh_b64_residue_1` | 正 | TCP/IPv4 | base64url 余 1 形态：wire 19B→b64 26 字符 | RFC 4648 §5+设计§3.4 | 9 |
| 26 | `doh_b64_residue_2` | 正 | TCP/IPv4 | base64url 余 2 形态：wire 20B→b64 27 字符 | RFC 4648 §5+设计§3.4 | 9 |
| 27 | `doh_dns_rcode_formerr` | 正 | TCP/IPv4 | RCODE=1 FORMERR（200 携带） | RFC 1035 §4.1.1+RFC 8484 §4.2.1 | 9 |
| 28 | `doh_dns_rcode_notimp` | 正 | TCP/IPv4 | RCODE=4 NOTIMP | RFC 1035 §4.1.1 | 9 |
| 29 | `doh_dns_rcode_refused` | 正 | TCP/IPv4 | RCODE=5 REFUSED | RFC 1035 §4.1.1 | 9 |
| 30 | `doh_dns_rcode_15_upper` | 正 | TCP/IPv4 | RCODE=15（4bit 值域上界） | RFC 1035 §4.1.1+设计§3.2 | 9 |
| 31 | `doh_dns_rd_zero` | 正 | TCP/IPv4 | 请求 RD=0（不期望递归） | RFC 1035 §4.1.1+设计§3.2 | 9 |
| 32 | `doh_dns_ra_zero` | 正 | TCP/IPv4 | 响应 RA=0（服务器不提供递归） | RFC 1035 §4.1.1+设计§3.2 | 9 |
| 33 | `doh_dns_aa_set` | 正 | TCP/IPv4 | 响应 AA=1（权威回答） | RFC 1035 §4.1.1+设计§3.2 | 9 |
| 34 | `doh_dns_question_txt` | 正 | TCP/IPv4 | QTYPE=TXT(16) | RFC 1035 §3.2.2+设计§3.3 | 9 |
| 35 | `doh_dns_question_mx` | 正 | TCP/IPv4 | QTYPE=MX(15) | RFC 1035 §3.2.2/§3.3.9+设计§3.3 | 9 |
| 36 | `doh_dns_qclass_ch` | 正 | TCP/IPv4 | QCLASS=CHAOS(3) 值域变体 | RFC 1035 §3.2.3+设计§3.3 | 9 |
| 37 | `doh_dns_answer_aaaa` | 正 | TCP/IPv4 | AAAA 答案（RDLENGTH=16） | RFC 1035 §4.1.3+设计§3.3 | 9 |
| 38 | `doh_dns_answer_cname_chain` | 正 | TCP/IPv4 | CNAME→A 两答案链 | RFC 1035 §3.3.6/§4.1.3+设计§3.3 | 9 |
| 39 | `doh_dns_answer_multi_types` | 正 | TCP/IPv4 | A+AAAA 双答案按配置次序 | RFC 1035 §4.1.3+设计§3.3 | 9 |
| 40 | `doh_dns_answer_svcb_alpn` | 正 | TCP/IPv4 | HTTPS SVCB AnswerForm（priority+target+alpn） | RFC 9460 §2.2+设计§3.3 | 9 |
| 41 | `doh_dns_answer_svcb_alias` | 正 | TCP/IPv4 | HTTPS SVCB AliasForm（priority 0+svc.example.net+空参数） | RFC 9460 §2.2+设计§3.3 | 9 |
| 42 | `doh_dns_answer_txt_strings` | 正 | TCP/IPv4 | TXT 多字符串段（每段前导 1B 长度） | RFC 1035 §3.3.14+设计§3.3 | 9 |
| 43 | `doh_dns_negative_cache_soa` | 正 | TCP/IPv4 | 负缓存：ANCOUNT=0+NSCOUNT=1+SOA+max-age=SOA MINIMUM | RFC 8484 §5.1+RFC 2308 §5+设计§3.6 | 9 |
| 44 | `doh_http_cache_age_header` | 正 | TCP/IPv4 | Age 头存在（§5.1 客户端须考虑） | RFC 8484 §5.1+设计§3.6 | 9 |
| 45 | `doh_http_mixed_get_post` | 正 | TCP/IPv4 | 同连接 POST→GET 混合；Content-Type 仅 POST | RFC 7230 §3.3.2+设计§3.1 泄漏规则 | 11 |
| 46 | `doh_http_host_explicit` | 正 | TCP/IPv4 | Host 显式域名（doh.example.com） | RFC 7230 §5.4+设计§3.1 | 9 |
| 47 | `doh_http_error_400_extra_param` | 正 | TCP/IPv4 | GET dns+多余查询参数→400（dns 唯一参数） | RFC 8484 §4.1+设计§3.1 | 9 |
| 48 | `doh_http_accept_absent` | 正 | TCP/IPv4 | 请求无 Accept 头（SHOULD 缺省合法形态） | RFC 8484 §4.1（SHOULD）+设计§3.1 | 9 |
| 49 | `doh_http_connection_close` | 正 | TCP/IPv4 | 单事务显式 Connection: close | RFC 7230 §6.3+设计§3.1/§5 | 9 |
| 50 | `doh_min_frame_get` | 正 | TCP/IPv4 | 最小 GET：根名 wire 17B→b64 23 字符（17≡2） | RFC 4648 §5+设计§3.5 | 9 |
| 51 | `doh_dns_ttl_zero` | 正 | TCP/IPv4 | TTL=0 边界 + max-age=0 | RFC 1035 §4.1.3+RFC 8484 §5.1+设计§8 | 9 |
| 52 | `doh_dns_ttl_max` | 正 | TCP/IPv4 | TTL=0xFFFFFFFF 满值 + max-age=4294967295 | RFC 1035 §4.1.3+RFC 8484 §5.1+设计§8 | 9 |
| 53 | `doh_dns_qname_label_63` | 正 | TCP/IPv4 | 单标签 63 字节上界（wire 65、CL=81） | RFC 1035 §3.1/§2.3.4+设计§8 | 9 |
| 54 | `doh_dns_qname_total_255` | 正 | TCP/IPv4 | 全名 255 字节上界（4 标签 63/63/63/61） | RFC 1035 §3.1/§2.3.4+设计§8 | 9 |
| 55 | `doh_dns_id_zero` | 正 | TCP/IPv4 | DNS ID=0 边界（RFC 8484 §4.1 SHOULD 值，本版有意偏离已声明） | RFC 1035 §4.1.1+RFC 8484 §4.1+设计§8 | 9 |
| 56 | `doh_dns_id_max` | 正 | TCP/IPv4 | DNS ID=65535 满值 | RFC 1035 §4.1.1+设计§8 | 9 |
| 57 | `doh_dns_id_one` | 正 | TCP/IPv4 | DNS ID=1 相邻值（最小+1 邻位） | RFC 1035 §4.1.1+需求v1.3 边界相邻值 | 9 |
| 58 | `doh_dns_id_65534` | 正 | TCP/IPv4 | DNS ID=65534 相邻值（最大-1 邻位） | RFC 1035 §4.1.1+需求v1.3 边界相邻值 | 9 |
| 59 | `doh_dns_ttl_one` | 正 | TCP/IPv4 | TTL=1 相邻值 + max-age=1 | RFC 1035 §4.1.3+需求v1.3 边界相邻值 | 9 |
| 60 | `doh_dns_ttl_4294967294` | 正 | TCP/IPv4 | TTL=4294967294 相邻值 | RFC 1035 §4.1.3+需求v1.3 边界相邻值 | 9 |
| 61 | `doh_dns_qname_254` | 正 | TCP/IPv4 | 全名 254 相邻值（下邻位） | RFC 1035 §3.1+需求v1.3 边界相邻值 | 9 |
| 62 | `doh_dns_qname_label_62` | 正 | TCP/IPv4 | 单标签 62 相邻值 | RFC 1035 §3.1+需求v1.3 边界相邻值 | 9 |
| 63 | `doh_http_cache_control_soa_minimum` | 正 | TCP/IPv4 | 负缓存 max-age=SOA MINIMUM（≤ 规则的恰值形态） | RFC 8484 §5.1+RFC 2308 §5+设计§3.6 | 9 |
| 64 | `doh_get_qname_max` | 正 | TCP/IPv4 | 255 名 GET 变体：wire 271B≡1 mod 3 无 padding 编码 | RFC 4648 §5+RFC 8484 §6+设计§8 | 9 |
| 65 | `doh_get_root_query` | 正 | TCP/IPv4 | 根名 GET 变体：wire 17B≡2 mod 3 无 padding 编码 | RFC 4648 §5+RFC 8484 §6+设计§3.3 | 9 |
| 66 | `doh_get_question_aaaa` | 正 | TCP/IPv4 | QTYPE=AAAA(28) 查询 GET 变体（b64 编码路径） | RFC 8484 §4.1+设计§3.3 | 9 |
| 67 | `doh_get_question_https` | 正 | TCP/IPv4 | QTYPE=HTTPS(65) GET 变体 | RFC 8484 §4.1+RFC 9460 | 9 |
| 68 | `doh_get_question_txt` | 正 | TCP/IPv4 | QTYPE=TXT(16) GET 变体 | RFC 8484 §4.1+设计§3.3 | 9 |
| 69 | `doh_get_question_mx` | 正 | TCP/IPv4 | QTYPE=MX(15) GET 变体 | RFC 8484 §4.1+设计§3.3 | 9 |
| 70 | `doh_get_rcode_formerr` | 正 | TCP/IPv4 | RCODE=1 GET 变体（2xx 承载任意 RCODE） | RFC 8484 §4.2.1+设计§4③ | 9 |
| 71 | `doh_get_rcode_notimp` | 正 | TCP/IPv4 | RCODE=4 GET 变体 | RFC 8484 §4.2.1 | 9 |
| 72 | `doh_get_rcode_refused` | 正 | TCP/IPv4 | RCODE=5 GET 变体 | RFC 8484 §4.2.1 | 9 |
| 73 | `doh_get_rcode_15` | 正 | TCP/IPv4 | RCODE=15 GET 变体（4bit 上界） | RFC 8484 §4.2.1+设计§3.2 | 9 |
| 74 | `doh_get_response_noerror` | 正 | TCP/IPv4 | NOERROR+A 答案 GET 变体 | RFC 8484 §4.2.2 | 9 |
| 75 | `doh_get_response_nxdomain` | 正 | TCP/IPv4 | NXDOMAIN GET 变体 | RFC 8484 §4.2.1 | 9 |
| 76 | `doh_get_response_servfail` | 正 | TCP/IPv4 | SERVFAIL GET 变体 | RFC 8484 §4.2.1 | 9 |
| 77 | `doh_get_answer_ttl` | 正 | TCP/IPv4 | A 答案结构 GET 变体 | RFC 1035 §4.1.3 | 9 |
| 78 | `doh_get_answer_aaaa` | 正 | TCP/IPv4 | AAAA 答案 GET 变体 | RFC 1035 §4.1.3 | 9 |
| 79 | `doh_get_answer_cname_chain` | 正 | TCP/IPv4 | CNAME→A 链 GET 变体 | RFC 1035 §3.3.6 | 9 |
| 80 | `doh_get_answer_svcb_alpn` | 正 | TCP/IPv4 | SVCB AnswerForm GET 变体 | RFC 9460 §2.2 | 9 |
| 81 | `doh_get_negative_cache_soa` | 正 | TCP/IPv4 | SOA 负缓存 GET 变体 | RFC 8484 §5.1+RFC 2308 §5 | 9 |
| 82 | `doh_get_rd_zero` | 正 | TCP/IPv4 | RD=0 GET 变体 | RFC 1035 §4.1.1 | 9 |
| 83 | `doh_get_aa_set` | 正 | TCP/IPv4 | AA=1 GET 变体 | RFC 1035 §4.1.1 | 9 |
| 84 | `doh_get_port_nondefault` | 正 | TCP/IPv4 | 非默认端口 8080 GET 变体 | 设计§2 端口变体声明 | 9 |
| 85 | `doh_neg_query_missing` | 负 | — | GET 配置缺 `dns` 参数（URI 无 query） | RFC 8484 §4.1+设计§7 | — |
| 86 | `doh_neg_base64_invalid` | 负 | — | base64url 含非法字符（`+`/`/`/非字母表字节） | RFC 4648 §5+设计§7 | — |
| 87 | `doh_neg_base64_padding` | 负 | — | base64url 带 `=` padding | RFC 8484 §6+设计§7 | — |
| 88 | `doh_neg_base64_truncated` | 负 | — | base64url 解码产出 <12B（解码链） | 设计§3.4/§7 | — |
| 89 | `doh_neg_dns_header_short` | 负 | — | POST body 原始 <12B（不经解码链） | RFC 1035 §4.1.1+设计§7 | — |
| 90 | `doh_neg_dns_qdcount_zero` | 负 | — | QDCOUNT=0（本版 validator 决策） | 设计§7 决策 | — |
| 91 | `doh_neg_dns_qname_overflow` | 负 | — | QNAME>255 或单标签>63 | RFC 1035 §3.1+设计§7 | — |
| 92 | `doh_neg_dns_question_truncated` | 负 | — | Question 缺零标签终止/QTYPE/QCLASS 截断 | RFC 1035 §4.1.2+设计§7 | — |
| 93 | `doh_neg_content_type` | 负 | — | Content-Type 非 application/dns-message | RFC 8484 §6+设计§7 | — |
| 94 | `doh_neg_method` | 负 | — | 方法非 POST/GET | RFC 8484 §4.1+设计§7 | — |
| 95 | `doh_neg_content_length` | 负 | — | POST Content-Length≠wire 字节/无 body | RFC 7230 §3.3.2+设计§7 | — |
| 96 | `doh_neg_layer_chain_missing_http` | 负 | — | 层链缺 http（tcp→doh 直连） | 设计§2/§7 | — |
| 97 | `doh_neg_port_conflict` | 负 | — | 端口/载体声明矛盾（明文 profile 配 443 等） | 设计§2/§7 | — |
| 98 | `doh_neg_response_id` | 负 | — | 响应 DNS ID≠请求 ID | RFC 1035 §4.1.1+设计§7 | — |
| 99 | `doh_neg_response_question` | 负 | — | 响应 Question 错配/2xx 无 DNS 体 | RFC 8484 §4.2.1+设计§7 | — |
| 100 | `doh_neg_wire_over_max` | 负 | — | 声明 DNS wire 总长 >65535 | RFC 8484 §6+设计§8 | — |
| 101 | `doh_neg_opcode_nonzero` | 负 | — | Opcode≠0（本版仅 QUERY） | RFC 1035 §4.1.1+设计§3.2 | — |
| 102 | `doh_neg_get_content_type` | 负 | — | GET 事务声明 Content-Type 头（无 body 载体禁） | RFC 7230 §3.3.2+设计§3.1 | — |
| 103 | `doh_neg_response_qr` | 负 | — | 响应事件声明 QR=0（响应必须 QR=1） | RFC 1035 §4.1.1+设计§5 | — |
| 104 | `doh_neg_z_nonzero` | 负 | — | Z 保留位非 0 | RFC 1035 §4.1.1+设计§3.2 | — |
| 105 | `doh_neg_rdlength_mismatch` | 负 | — | Answer RDLENGTH≠RDATA 实际字节 | RFC 1035 §4.1.3+设计§3.3 | — |
| 106 | `doh_neg_ancount_mismatch` | 负 | — | ANCOUNT≠声明答案数 | RFC 1035 §4.1.1+设计§3.2 | — |
| 107 | `doh_neg_qdcount_multi` | 负 | — | QDCOUNT>1（本版恒 1） | 设计§3.2 决策 | — |
| 108 | `doh_neg_dns_id_range` | 负 | — | dns_id 声明 65536（16-bit 上界 +1 越界） | RFC 1035 §4.1.1+需求v1.3 边界相邻值 | — |
| 109 | `doh_neg_ttl_range` | 负 | — | TTL 声明 4294967296（2^32 越界） | RFC 1035 §4.1.3+需求v1.3 边界相邻值 | — |
| 110 | `doh_neg_qtype_token` | 负 | — | qtype/qclass 非数字 token（BOGUS） | RFC 1035 §3.2.2+设计§3.3 v2.2 决策 | — |

（`packet_count` 约定值按 §1 统一公式 3+N+4：单事务 9；同连接 2 事务 11、3 事务 13；并发/多会话 18；MSS 用例 ≥10 按实际分段校准。约定数字为实现基线，实现 ACK 合并/分段不同时同步四件套。）

## 3. 线上编码和偏移断言

层链 `[tcp, http, doh]`，无 VLAN/IP options/TCP options 时 HTTP 起行 IPv4 offset 54、IPv6 offset 74。**DNS wire 在 HTTP body 内，偏移不固定**：body 起点 = 54/74 + 该 fixture 固定 HTTP 头集合字节长（头集合由配置钉死，偏移可预算）。断言分层：

1. **HTTP 起行与头（fields 权威断言）**：请求帧 offset 54 起为 ASCII（POST：`50 4F 53 54 20 2F 64 6E 73 2D 71 75 65 72 79 20`（`POST /dns-query `）；GET：`47 45 54 20 2F 64 6E 73 2D 71 75 65 72 79 3F 64 6E 73 3D`（`GET /dns-query?dns=`））。字段断言用 `http.request.method`/`http.request.uri`/`http.request.uri.path`/`http.content_type`/`http.content_length`/`http.accept`/`http.host`；GET 的 query 用 `http.request.uri.query.parameter`（实测名含 `dns=<b64>`）。
2. **DNS wire（`http.file_data` + 自动内层 `dns.*` 双通道）**：`http.file_data` nonzero 证明 body 存在；响应帧（2xx + `Content-Type: application/dns-message`）**自动内层解码**，`dns.id`/`dns.qry.name`/`dns.qry.type`/`dns.qry.class`/`dns.count.queries`/`dns.count.answers` 实测可见（tshark 3.6.14 实证）；POST 请求 body 同样自动内层解码。DNS 头 12B 的十六进制常量用 frames 断言：`ID` 两字节按 fixture、`flags` 请求 `01 00`（RD）+ 响应 `81 80`（QR|RD|RA|RCODE=0）、`QDCOUNT=00 01`。GET 请求帧无 `dns.*`（实测），其 wire 内容断言 = query 参数 base64url 文本（`http.request.uri.query.parameter` 含 `dns=`）+ 解码后与响应 Question 一致的帧间关系（响应 `dns.qry.name` 与请求 base64 解码名一致，通过 fixture 固定名断言）。
3. **TCP 分段与重组**：分段边界不是 HTTP/DNS 边界（RFC 7230 §3.3.2）——跨段时先按 `tcp.stream` 重组，再对重组后末帧断言完整 HTTP+DNS（`http.content_length`=body 实际长、`dns.count.answers` 与配置一致）。
4. **has_payload 语义**：权威断言是 `http.file_data` nonzero + 响应帧 `dns.*` 字段非空 + frames hex；`frame.len>80` 只作宽松代理，不得以包数/PSH 标志替代。
5. **多会话包号规则**：`sessions[]` 按多会话展开整块回放，第二会话 TCP 握手包号 = 前一会话总包数 + 1；断言跨会话关联用 `tcp.stream` 区分，不硬编码全局包号。

## 4. 正例逐项断言契约

约定 packet_count 见 §2 表；以下 fields/frames 为最低断言集，实现期可增不可减。默认 fixture 地址 `192.0.2.66 → 198.51.100.66`、`dst_port=80`；查询 `www.example.com`（wire 33B）；响应 A 记录 `192.0.2.1` TTL=300（wire 64B）。`same_as_packet` 指同 `tcp.stream` 对侧帧同字段同值。

1. **`doh_post_ipv4_http11`**（TCP/IPv4，packet_count=9）：握手三帧；帧 4 `http.request.method=POST`、`http.request.uri.path=/dns-query`、`http.content_type=application/dns-message`、`http.content_length` nonzero（精确值归 #16 专断）、`http.accept=application/dns-message`、`http.host=198.51.100.66`（缺省 Host=dst_ip）；请求帧 `http.file_data` nonzero + `dns.id`/`dns.qry.name=www.example.com`（自动内层解码）；帧 5 `http.response.code=200`、`http.content_type=application/dns-message`、`dns.id` same_as、`dns.flags.response=1`、`dns.flags.rcode=0`、`dns.count.answers=1`；挥手 4 帧。
2. **`doh_get_ipv4_base64url`**（TCP/IPv4，packet_count=9）：帧 4 `http.request.method=GET`、`http.request.uri` 以 `/dns-query?dns=` 开头、`http.request.uri.query.parameter` 恰一个 `dns=<b64>`、b64 无 `+`/`/`/`=`、`http.content_length=0`、无 `http.file_data`、无 Content-Type；帧 5 响应 `dns.qry.name=www.example.com` 与请求 fixture 名一致、`dns.id` 与 fixture 固定 ID 一致；挥手。
3. **`doh_post_ipv6_http11`**（TCP/IPv6，packet_count=9）：`ipv6.nxt=6`、HTTP 起行 offset 74；POST 断言面同 #1；不出现 `ip.version=4`。
4. **`doh_get_ipv6_base64url`**（TCP/IPv6，packet_count=9）：IPv6 独立地址显式给出；断言同 #2（偏移 74、query 无 padding、响应 Question 一致）。
5. **`doh_dns_header_query`**（TCP/IPv4，packet_count=9）：请求帧：`dns.flags.response=0`、`dns.flags.opcode=0`、`dns.flags.truncated=0`、`dns.flags.recdesired=1`、`dns.flags.z=0`、`dns.count.queries=1`、`dns.count.answers=0`、`dns.count.auth_rr=0`、`dns.count.add_rr=0`；响应帧：`dns.flags.authoritative=0`、TC/Z/auth_rr/add_rr 双侧 0；frames：ID 两字节 fixture、flags `01 00`、QDCOUNT `00 01`、ANCOUNT/NSCOUNT/ARCOUNT 六字节 `00`。
6. **`doh_dns_question_a`**（TCP/IPv4，packet_count=9）：`dns.qry.name=www.example.com`、`dns.qry.name.len=15`（展示长）、`dns.qry.type=1`、`dns.qry.class=1`；frames QNAME 前缀 `03 77 77 77`、根 `00`、QTYPE `00 01`、QCLASS `00 01`。
7. **`doh_dns_question_aaaa`**（TCP/IPv4，packet_count=9）：`dns.qry.type=28`；响应 `dns.resp.type=28`、`dns.aaaa` 为配置 IPv6。
8. **`doh_dns_question_https`**（TCP/IPv4，packet_count=9）：`dns.qry.type=65`；响应 `dns.resp.type=65`。
9. **`doh_dns_question_root`**（TCP/IPv4，packet_count=9）：`dns.qry.name=<Root>`、`dns.count.labels=1`、`http.content_length=17`、frames QNAME 首字节 `00`。
10. **`doh_dns_response_noerror`**（TCP/IPv4，packet_count=9）：响应 `dns.flags.response=1`、`dns.flags.rcode=0`、`dns.flags.recavail=1`、`dns.id` same_as、`dns.count.queries=1`、`dns.count.answers=1`。
11. **`doh_dns_response_nxdomain`**（TCP/IPv4，packet_count=9）：`http.response.code=200`、`dns.flags.rcode=3`、`dns.count.answers=0`。
12. **`doh_dns_response_servfail`**（TCP/IPv4，packet_count=9）：`http.response.code=200`、`dns.flags.rcode=2`、`dns.count.answers=0`。
13. **`doh_dns_answer_ttl`**（TCP/IPv4，packet_count=9）：`dns.count.answers=1`、`dns.resp.type=1`、`dns.resp.class=1`、`dns.resp.ttl=300`、`dns.a=192.0.2.1`；frames TTL `00 00 01 2C`、RDLENGTH `00 04`、RDATA `C0 00 02 01`。
14. **`doh_http_keepalive_multi_transaction`**（TCP/IPv4，packet_count=13）：单 `tcp.stream` ≥3 笔（A→AAAA→HTTPS）请求/响应 1:1 交替无 pipelining；每笔请求 `Connection: keep-alive`、末笔按配置（默认 close）；每响应 `dns.id` same_as 对应请求。
15. **`doh_http_content_length_exact`**（TCP/IPv4，packet_count=9）：`http.content_length=33`（请求）/`=64`（响应）；frames header 行 `43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 33 33`（`Content-Length: 33`）。精确值仅本例专断。
16. **`doh_http_cache_control`**（TCP/IPv4，packet_count=9）：fixture 两答案 TTL 不同（300/60）：`http.cache_control` 含 `max-age=60` 恰等于**最小** TTL（RFC 8484 §5.1，C10 实 fixture 断言非括号声明）；frames 断言两答案 TTL 字节 `00 00 01 2C`/`00 00 00 3C`。
17. **`doh_http_error_400`**（TCP/IPv4，packet_count=9）：`response.status:400` 通道；`http.response.code=400`、`http.content_length=0`、无 `http.file_data`、无 `dns.*` 响应字段、无 Content-Type/Cache-Control（非 2xx 头集合，设计 §3.1）。
18. **`doh_http_error_404`**（TCP/IPv4，packet_count=9）：`http.response.code=404`、空 body、无 `dns.*`、非 2xx 头集合。
19. **`doh_http_error_415`**（TCP/IPv4，packet_count=9）：POST `Content-Type: text/plain`；`http.response.code=415`、空 body、无 `dns.*`。
20. **`doh_mss_large_response`**（TCP/IPv4，packet_count=校准≥10）：响应多 Answer（20 条 A 或长 TXT）跨 ≥2 分段；重组后 `http.content_length`=实际长、`dns.count.answers` 与配置一致、frames 尾字节=末 RDATA。
21. **`doh_multi_session`**（TCP/IPv4，packet_count=18）：两会话不同源端口；`tcp.stream` distinct；第二会话握手包号=10；各会话 Question 匹配本会话请求。
22. **`doh_port_nondefault_post`**（TCP/IPv4，packet_count=9）：`tcp.dstport=8080`；其余断言面同 #1（端口由配置覆盖，planner 不得静默改写）。
23. **`doh_port_nondefault_get`**（TCP/IPv4，packet_count=9）：`tcp.dstport=8080`；其余断言面同 #2。
24. **`doh_concurrent_sessions`**（TCP/IPv4×2，packet_count=18）：双 `tcp.stream` 交错回放；DNS ID/QNAME/事务状态互不串用；两会话各自完整请求/响应对。
25. **`doh_b64_residue_1`**（TCP/IPv4，packet_count=9）：QNAME 单字符 `a`（wire=12+3+4=19，19 mod 3=1）；query 参数值恰 26 字符、无 padding；响应 `http.content_length=19`。
26. **`doh_b64_residue_2`**（TCP/IPv4，packet_count=9）：QNAME `ab`（wire=20，20 mod 3=2）；参数值恰 27 字符、无 padding；响应 `http.content_length=20`。（余 0 形态见 #2 wire 33→44）
27. **`doh_dns_rcode_formerr`**（TCP/IPv4，packet_count=9）：`dns.flags.rcode=1`、`http.response.code=200`、`dns.count.answers=0`。
28. **`doh_dns_rcode_notimp`**（TCP/IPv4，packet_count=9）：`dns.flags.rcode=4`、`dns.count.answers=0`。
29. **`doh_dns_rcode_refused`**（TCP/IPv4，packet_count=9）：`dns.flags.rcode=5`、`dns.count.answers=0`。
30. **`doh_dns_rcode_15_upper`**（TCP/IPv4，packet_count=9）：`dns.flags.rcode=15`、`dns.count.answers=0`；flags 低半字节 `0F`。
31. **`doh_dns_rd_zero`**（TCP/IPv4，packet_count=9）：请求 `dns.flags.recdesired=0`；frames flags `00 00`。
32. **`doh_dns_ra_zero`**（TCP/IPv4，packet_count=9）：响应 `dns.flags.recavail=0`、`dns.flags.response=1`。
33. **`doh_dns_aa_set`**（TCP/IPv4，packet_count=9）：响应 `dns.flags.authoritative=1`；frames flags `85 80`（QR|AA，保留基线 RD|RA）。
34. **`doh_dns_question_txt`**（TCP/IPv4，packet_count=9）：`dns.qry.type=16`；响应 `dns.resp.type=16`。
35. **`doh_dns_question_mx`**（TCP/IPv4，packet_count=9）：`dns.qry.type=15`；响应 MX 答案偏好 2B 大端+交换名。
36. **`doh_dns_qclass_ch`**（TCP/IPv4，packet_count=9）：`dns.qry.class=3`；响应 QCLASS 回带同值。
37. **`doh_dns_answer_aaaa`**（TCP/IPv4，packet_count=9）：`dns.aaaa=2001:db8::1`、`dns.resp.type=28`、frames RDLENGTH `00 10`、RDATA 16B。
38. **`doh_dns_answer_cname_chain`**（TCP/IPv4，packet_count=9）：`dns.count.answers=2`；答案 1 TYPE=5 CNAME（RDATA=label 编码目标名）、答案 2 TYPE=1 A。
39. **`doh_dns_answer_multi_types`**（TCP/IPv4，packet_count=9）：`dns.count.answers=2`、`dns.a` 与 `dns.aaaa` 各一、次序与配置一致。
40. **`doh_dns_answer_svcb_alpn`**（TCP/IPv4，packet_count=9）：RDATA：SvcPriority 2B 大端+TargetName label 编码+SvcParam（key `00 01` alpn+len+`68 32`（h2））；`dns.resp.type=65`。
41. **`doh_dns_answer_svcb_alias`**（TCP/IPv4，packet_count=9）：RDATA：`00 00`（SvcPriority 0）+`03 73 76 63 07 65 78 61 6d 70 6c 65 03 6e 65 74 00`（TargetName `svc.example.net` label 编码 17B）+空 SvcParams；RDLENGTH=19。
42. **`doh_dns_answer_txt_strings`**（TCP/IPv4，packet_count=9）：RDATA 两段 character-string（各段前导长度字节）；`dns.resp.type=16`。
43. **`doh_dns_negative_cache_soa`**（TCP/IPv4，packet_count=9）：`dns.count.answers=0`、`dns.count.auth_rr=1`；Authority SOA RDATA（MNAME/RNAME label 编码+Serial/Refresh/Retry/Expire/MINIMUM 各 4B 大端，MINIMUM=`00 00 00 3C`）；frames 断言 SOA TYPE `00 06`。
44. **`doh_http_cache_age_header`**（TCP/IPv4，packet_count=9）：响应行含 `Age: 60`（frames `41 67 65 3A 20 36 30`）；`max-age` 仍=TTL。
45. **`doh_http_mixed_get_post`**（TCP/IPv4，packet_count=11）：帧序 POST/200/GET/200 同 `tcp.stream` 严格交替；POST 帧 `http.content_type=application/dns-message`；**GET 帧 Content-Type 缺席断言不在本例**——tshark 3.6.14 会话级显示泄漏（rr-doh D10 实测：同流先前 POST 的 Content-Type 会显示在后继 GET 帧），缺席断言在独立 GET 流（用例 2「无 Content-Type」）承载；GET `http.content_length=0`。
46. **`doh_http_host_explicit`**（TCP/IPv4，packet_count=9）：`http.host=doh.example.com`（非 dst_ip 缺省）；其余同基线。
47. **`doh_http_error_400_extra_param`**（TCP/IPv4，packet_count=9）：URI `/dns-query?dns=<b64>&foo=bar`；响应 400 空 body 无 `dns.*`。
48. **`doh_http_accept_absent`**（TCP/IPv4，packet_count=9）：请求无 `http.accept` 字段；响应正常 2xx+DNS wire（Accept 缺失不进负例）。
49. **`doh_http_connection_close`**（TCP/IPv4，packet_count=9）：请求帧 `http.request.line` 含 `Connection: close`；响应后即挥手。
50. **`doh_min_frame_get`**（TCP/IPv4，packet_count=9）：query 参数值恰 23 字符（wire 17B≡2，ceil(17×4/3)=23，无 padding）；响应 `http.content_length=17`；全帧最小形态。
51. **`doh_dns_ttl_zero`**（TCP/IPv4，packet_count=9）：`dns.resp.ttl=0`、`http.cache_control` 含 `max-age=0`。
52. **`doh_dns_ttl_max`**（TCP/IPv4，packet_count=9）：`dns.resp.ttl=4294967295`（实测可解析满值）、`http.cache_control` 含 `max-age=4294967295`。
53. **`doh_dns_qname_label_63`**（TCP/IPv4，packet_count=9）：`dns.qry.name.len=63`（展示）、`http.content_length=81`（12+65+4）。
54. **`doh_dns_qname_total_255`**（TCP/IPv4，packet_count=9）：`http.content_length=271`（12+255+4，权威断言）；`dns.qry.name.len` 展示 253 仅辅助。
55. **`doh_dns_id_zero`**（TCP/IPv4，packet_count=9）：请求/响应 `dns.id=0` same_as。
56. **`doh_dns_id_max`**（TCP/IPv4，packet_count=9）：请求/响应 `dns.id=65535` same_as。
57. **`doh_dns_id_one`**（TCP/IPv4，packet_count=9）：请求/响应 `dns.id=1` same_as。
58. **`doh_dns_id_65534`**（TCP/IPv4，packet_count=9）：请求/响应 `dns.id=65534` same_as。
59. **`doh_dns_ttl_one`**（TCP/IPv4，packet_count=9）：`dns.resp.ttl=1`、`http.cache_control` 含 `max-age=1`。
60. **`doh_dns_ttl_4294967294`**（TCP/IPv4，packet_count=9）：`dns.resp.ttl=4294967294`、`max-age=4294967294`。
61. **`doh_dns_qname_254`**（TCP/IPv4，packet_count=9）：`http.content_length=270`（12+254+4）。
62. **`doh_dns_qname_label_62`**（TCP/IPv4，packet_count=9）：`http.content_length=80`（12+64+4）。
63. **`doh_http_cache_control_soa_minimum`**（TCP/IPv4，packet_count=9）：同 SOA fixture：`http.cache_control` 含 `max-age=60` 恰等于 SOA MINIMUM（负响应新鲜度不得大于 MINIMUM 的恰值形态）。
64. **`doh_get_qname_max`**（TCP/IPv4，packet_count=9）：`http.request.uri.query.parameter` 值长 = ceil(271*4/3)=362、不含 `=`（residue 1 边界：标准 base64 需补 1 个 `=` 被禁止的形态）；响应 `dns.qry.name` 一致。
65. **`doh_get_root_query`**（TCP/IPv4，packet_count=9）：参数值长 = ceil(17*4/3)=23、不含 `=`（residue 2 形态）；响应 `http.content_length=17`。
66. **`doh_get_question_aaaa`**（TCP/IPv4，packet_count=9）：GET 载体断言（query 参数无 padding/CL:0/无 Content-Type）+`dns.qry.type` 解码一致（fixture 固定名/类型经实现侧解码校验）；响应 `dns.resp.type=28`。
67. **`doh_get_question_https`**（TCP/IPv4，packet_count=9）：同上 GET 断言面；响应 `dns.resp.type=65`。
68. **`doh_get_question_txt`**（TCP/IPv4，packet_count=9）：同上；响应 `dns.resp.type=16`。
69. **`doh_get_question_mx`**（TCP/IPv4，packet_count=9）：同上；响应 MX 答案。
70. **`doh_get_rcode_formerr`**（TCP/IPv4，packet_count=9）：GET 请求；响应 200+`dns.flags.rcode=1`。
71. **`doh_get_rcode_notimp`**（TCP/IPv4，packet_count=9）：GET 请求；响应 `dns.flags.rcode=4`。
72. **`doh_get_rcode_refused`**（TCP/IPv4，packet_count=9）：GET 请求；响应 `dns.flags.rcode=5`。
73. **`doh_get_rcode_15`**（TCP/IPv4，packet_count=9）：GET 请求；响应 `dns.flags.rcode=15`。
74. **`doh_get_response_noerror`**（TCP/IPv4，packet_count=9）：GET 请求；响应 `dns.flags.rcode=0`、`dns.a`、ID same_as。
75. **`doh_get_response_nxdomain`**（TCP/IPv4，packet_count=9）：GET 请求；响应 200+`dns.flags.rcode=3`、`dns.count.answers=0`。
76. **`doh_get_response_servfail`**（TCP/IPv4，packet_count=9）：GET 请求；响应 `dns.flags.rcode=2`。
77. **`doh_get_answer_ttl`**（TCP/IPv4，packet_count=9）：GET 请求；响应 `dns.resp.ttl=300`、`dns.a=192.0.2.1`、RDLENGTH/RDATA frames。
78. **`doh_get_answer_aaaa`**（TCP/IPv4，packet_count=9）：GET 请求；响应 `dns.aaaa`、RDLENGTH `00 10`。
79. **`doh_get_answer_cname_chain`**（TCP/IPv4，packet_count=9）：GET 请求；响应 `dns.count.answers=2` CNAME+A。
80. **`doh_get_answer_svcb_alpn`**（TCP/IPv4，packet_count=9）：GET 请求；响应 SVCB RDATA（priority+target+alpn）。
81. **`doh_get_negative_cache_soa`**（TCP/IPv4，packet_count=9）：GET 请求；响应 ANCOUNT=0+`dns.count.auth_rr=1`+`max-age=60`。
82. **`doh_get_rd_zero`**（TCP/IPv4，packet_count=9）：GET 请求帧 query 参数 = fixture 预计算 b64 定值（`www.example.com` 33B wire→44 字符，解码首 flags 字节 `00` 即 RD=0）；断言该定值 + 响应 `dns.qry.name=www.example.com` 一致。
83. **`doh_get_aa_set`**（TCP/IPv4，packet_count=9）：GET 请求；响应 `dns.flags.authoritative=1`。
84. **`doh_get_port_nondefault`**（TCP/IPv4，packet_count=9）：`tcp.dstport=8080`；GET 断言面同 #2。

## 5. 负例契约

负例必须在 planner/validator 失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP/HTTP 外壳的假成功；执行期 `expect` 严格只有 `expect_error`、`error_contains`。主锚词与设计 §7 表（26 行）一一对应；**注册 doh 层时每行钉死单一 error_contains（取主锚词），四件套同步**：

| # | ID | `wire_fault` 注入口 | 故障输入 | 主锚词（备选） | 依据 |
|---:|---|---|---|---|---|
| 0 | `doh_neg_query_missing` | `query_missing` | GET 配置缺 `dns` 参数（URI 无 query） | `dns`（备选 query/parameter） | RFC 8484 §4.1+设计§7 |
| 1 | `doh_neg_base64_invalid` | `base64` | base64url 含非法字符（`+`/`/`/非字母表字节） | `base64`（备选 url/decode） | RFC 4648 §5+设计§7 |
| 2 | `doh_neg_base64_padding` | `padding` | base64url 带 `=` padding | `base64`（备选 padding/url） | RFC 8484 §6+设计§7 |
| 3 | `doh_neg_base64_truncated` | `b64_short` | base64url 解码产出 <12B（解码链） | `decode`（备选 truncate/length） | 设计§3.4/§7 |
| 4 | `doh_neg_dns_header_short` | `dns_header_short` | POST body 原始 <12B（不经解码链） | `dns`（备选 header/length） | RFC 1035 §4.1.1+设计§7 |
| 5 | `doh_neg_dns_qdcount_zero` | `qdcount` | QDCOUNT=0（本版 validator 决策） | `question`（备选 qdcount/dns） | 设计§7 决策 |
| 6 | `doh_neg_dns_qname_overflow` | `qname` | QNAME>255 或单标签>63 | `qname`（备选 label/length） | RFC 1035 §3.1+设计§7 |
| 7 | `doh_neg_dns_question_truncated` | `question_truncated` | Question 缺零标签终止/QTYPE/QCLASS 截断 | `question`（备选 wire/length） | RFC 1035 §4.1.2+设计§7 |
| 8 | `doh_neg_content_type` | `content_type` | Content-Type 非 application/dns-message | `content-type`（备选 media/type） | RFC 8484 §6+设计§7 |
| 9 | `doh_neg_method` | `method` | 方法非 POST/GET | `method`（备选 http） | RFC 8484 §4.1+设计§7 |
| 10 | `doh_neg_content_length` | `content_length` | POST Content-Length≠wire 字节/无 body | `content-length`（备选 length/body/dns） | RFC 7230 §3.3.2+设计§7 |
| 11 | `doh_neg_layer_chain_missing_http` | `layer_chain` | 层链缺 http（tcp→doh 直连） | `carrier`（备选 layer） | 设计§2/§7 |
| 12 | `doh_neg_port_conflict` | `port_conflict` | 端口/载体声明矛盾（明文 profile 配 443 等） | `port`（备选 carrier） | 设计§2/§7 |
| 13 | `doh_neg_response_id` | `response_id` | 响应 DNS ID≠请求 ID | `id`（备选 match/correlation） | RFC 1035 §4.1.1+设计§7 |
| 14 | `doh_neg_response_question` | `response_question` | 响应 Question 错配/2xx 无 DNS 体 | `question`（备选 match/body/wire） | RFC 8484 §4.2.1+设计§7 |
| 15 | `doh_neg_wire_over_max` | `wire_over_max` | 声明 DNS wire 总长 >65535 | `length`（备选 max/wire） | RFC 8484 §6+设计§8 |
| 16 | `doh_neg_opcode_nonzero` | `opcode_nonzero` | Opcode≠0（本版仅 QUERY） | `opcode`（备选 value） | RFC 1035 §4.1.1+设计§3.2 |
| 17 | `doh_neg_get_content_type` | `get_content_type` | GET 事务声明 Content-Type 头（无 body 载体禁） | `content-type`（备选 get/header） | RFC 7230 §3.3.2+设计§3.1 |
| 18 | `doh_neg_response_qr` | `response_qr` | 响应事件声明 QR=0（响应必须 QR=1） | `response`（备选 qr/flag） | RFC 1035 §4.1.1+设计§5 |
| 19 | `doh_neg_z_nonzero` | `z_nonzero` | Z 保留位非 0 | `z`（备选 flag/value） | RFC 1035 §4.1.1+设计§3.2 |
| 20 | `doh_neg_rdlength_mismatch` | `rdlength_mismatch` | Answer RDLENGTH≠RDATA 实际字节 | `rdlength`（备选 length/answer） | RFC 1035 §4.1.3+设计§3.3 |
| 21 | `doh_neg_ancount_mismatch` | `ancount_mismatch` | ANCOUNT≠声明答案数 | `ancount`（备选 count） | RFC 1035 §4.1.1+设计§3.2 |
| 22 | `doh_neg_qdcount_multi` | `qdcount_multi` | QDCOUNT>1（本版恒 1） | `qdcount`（备选 question） | 设计§3.2 决策 |
| 23 | `doh_neg_dns_id_range` | `dns_id_range` | dns_id 声明 65536（16-bit 上界 +1 越界） | `id`（备选 range/value） | RFC 1035 §4.1.1+需求v1.3 边界相邻值 |
| 24 | `doh_neg_ttl_range` | `ttl_range` | TTL 声明 4294967296（2^32 越界） | `ttl`（备选 range/value） | RFC 1035 §4.1.3+需求v1.3 边界相邻值 |
| 25 | `doh_neg_qtype_token` | `qtype_token` | qtype/qclass 非数字 token（BOGUS） | `qtype`（备选 value/token） | RFC 1035 §3.2.2+设计§3.3 v2.2 决策 |

**合并说明（C4 修复保留）**：`body_missing`/`http200_no_dns` 分支不设独立 ID（由 `content_length`/`response_question` 覆盖）。**原 `doh_neg_carrier_port` 拆为 `doh_neg_layer_chain_missing_http`/`doh_neg_port_conflict` 两原子例（v3.0.1）**。v2.2 扩面合计 26 行，与设计 §7 一一对应、同序。

合法协议事件不进负例（防误报）：HTTP 400/404/415 错误响应本身、DNS RCODE 0–15 全值域、TTL=0/满值、Cache-Control 缺失（SHOULD）、Accept 缺失（SHOULD）、DNS ID 0/满值、根 QNAME、GET 与 POST 并存、非默认端口、未知数值 QTYPE/QCLASS（数值透传合法，仅非数字 token 拒绝）。

## 6. 五层覆盖映射（v1.3 行为面对照，按 ID 引用防错位）

| 层面 | 用例 ID | 说明 |
|---|---|---|
| 功能 | 基线族（doh_post_ipv4_http11 / doh_get_ipv4_base64url / doh_post_ipv6_http11 / doh_get_ipv6_base64url）、头字段（doh_dns_header_query）、Question/Answer 族（doh_dns_question_* / doh_dns_answer_*）、RCODE 族（doh_dns_rcode_*/doh_dns_response_*）、标志族（doh_dns_rd_zero / ra_zero / aa_set）、负缓存（doh_dns_negative_cache_soa）、HTTP 形态（doh_http_*）、GET 变体族（doh_get_*）；负例全部 26 条 | GET/POST 双载体 × DNS 特性点系统性展开；26 条负例逐故障输入 |
| 性能 | doh_mss_large_response、doh_dns_qname_label_63 / total_255 / label_62 / qname_254、doh_neg_wire_over_max | 大响应跨 MSS 分段重组；QNAME 上界+相邻；大请求不适用（请求 wire ≤~275B，设计 §4 声明）；RST 不适用（设计 §4 声明） |
| 数据场景 | doh_dns_id_* / ttl_* / qname_* 边界族、doh_dns_rcode_* 值域、doh_b64_residue_* / get_qname_max / get_root_query（三余数）、doh_dns_answer_svcb_* / txt_strings、soa MINIMUM、min_frame_get | 边界相邻值逐点（需求 v1.3 §4） |
| 地址与流 | doh_post/get_ipv4/ipv6（v4+v6）、doh_multi_session、doh_port_nondefault_post/get、doh_concurrent_sessions | 默认/非默认端口、并发会话 v2.2 翻案纳入；流关联/多流不适用（设计 §4 声明） |
| 业务 | 解析器查询、HTTPS/SVCB 现网（question_https + answer_svcb_* + get 变体）、长连接（keepalive）、缓存策略（cache_control / cache_age_header / cache_control_soa_minimum）、混合事务（mixed_get_post）、错误形态（error_400/404/415/400_extra_param） | 现网 DoH 解析器典型场景优先 |

## 7. 机器契约与静态检查

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/doh.json` 通过；当前数组恰含 1 条 `doh_neg_unregistered`：`proto=doh`、层链 `[{"tcp":{},{"http":{},{"doh":{}}]`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。
2. 实现注册 `doh` 层后：移除占位，按 §2 顺序补入 111 个语义用例（85 正 + 26 负）；ID、顺序与本文 §2 一致（脚本核验）；设计行/待实现边界不得写入 JSON ID 集合。
3. 正例每条含 `packet_count`（或 `min_packets`）+ `fields` + `frames`；`fields` 只用 §1 实测存在的 tshark 字段，不伪造 `doh.*`；DNS 断言走 `http.file_data` + 自动内层 `dns.*` 双通道；GET 请求侧 DNS 用 `http.request.uri.query.parameter` + frames hex。`packet_count` 按 §1 公式 3+N+4。
4. 负例 `expect` 键集合恰为 `{expect_error, error_contains}`；error_contains 取 §5 表主锚词（注册时钉死）。
5. 断言包号跨会话/连接时用 `tcp.stream`+会话起点规则；动态值用 `same_as_packet`/`distinct_values`/`nonzero`。
6. GET 请求帧不得臆造 `dns.*` 字段；实现期若改用 `-d` 强制解码，四件套同步更新。

## 8. 三方一致性表

设计 §9（ID 权威=本文 §2）、本文 §2、实现后 `doh.json` 保持同一 111 个语义 ID、同一顺序（当前 JSON 另有占位，不计入）：

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
doh_http_keepalive_multi_transaction
doh_http_content_length_exact
doh_http_cache_control
doh_http_error_400
doh_http_error_404
doh_http_error_415
doh_mss_large_response
doh_multi_session
doh_port_nondefault_post
doh_port_nondefault_get
doh_concurrent_sessions
doh_b64_residue_1
doh_b64_residue_2
doh_dns_rcode_formerr
doh_dns_rcode_notimp
doh_dns_rcode_refused
doh_dns_rcode_15_upper
doh_dns_rd_zero
doh_dns_ra_zero
doh_dns_aa_set
doh_dns_question_txt
doh_dns_question_mx
doh_dns_qclass_ch
doh_dns_answer_aaaa
doh_dns_answer_cname_chain
doh_dns_answer_multi_types
doh_dns_answer_svcb_alpn
doh_dns_answer_svcb_alias
doh_dns_answer_txt_strings
doh_dns_negative_cache_soa
doh_http_cache_age_header
doh_http_mixed_get_post
doh_http_host_explicit
doh_http_error_400_extra_param
doh_http_accept_absent
doh_http_connection_close
doh_min_frame_get
doh_dns_ttl_zero
doh_dns_ttl_max
doh_dns_qname_label_63
doh_dns_qname_total_255
doh_dns_id_zero
doh_dns_id_max
doh_dns_id_one
doh_dns_id_65534
doh_dns_ttl_one
doh_dns_ttl_4294967294
doh_dns_qname_254
doh_dns_qname_label_62
doh_http_cache_control_soa_minimum
doh_get_qname_max
doh_get_root_query
doh_get_question_aaaa
doh_get_question_https
doh_get_question_txt
doh_get_question_mx
doh_get_rcode_formerr
doh_get_rcode_notimp
doh_get_rcode_refused
doh_get_rcode_15
doh_get_response_noerror
doh_get_response_nxdomain
doh_get_response_servfail
doh_get_answer_ttl
doh_get_answer_aaaa
doh_get_answer_cname_chain
doh_get_answer_svcb_alpn
doh_get_negative_cache_soa
doh_get_rd_zero
doh_get_aa_set
doh_get_port_nondefault
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
doh_neg_layer_chain_missing_http
doh_neg_port_conflict
doh_neg_response_id
doh_neg_response_question
doh_neg_wire_over_max
doh_neg_opcode_nonzero
doh_neg_get_content_type
doh_neg_response_qr
doh_neg_z_nonzero
doh_neg_rdlength_mismatch
doh_neg_ancount_mismatch
doh_neg_qdcount_multi
doh_neg_dns_id_range
doh_neg_ttl_range
doh_neg_qtype_token
```

## 9. 修订记录

- v3.0.1（2026-09-01，rr-doh 全清单对账轮）：按 rr-doh ①枚举全表（135 点）/②C0–C11/③D1–D12 逐条落地。**C 清单**：C1 非默认端口（25/26）、C2 GET 余数边界（`doh_get_qname_max` 271B≡1/`doh_get_root_query` 17B≡2）、C3 拆 SOA wire 形状与 max-age 恰值两例、C4 RST 不适用声明（设计 §4）、C5 RCODE 1/4/5/15、C6 dns_id/ttl 越界负例、C7 TXT/MX + 未知 token validator 决策（`doh_neg_qtype_token`）、C8 Host 默认断言入 #1、C9 RD=0/RA=0/AA=1、C10 max-age 多答案取最小实 fixture、C11 混合事务（#51）+ 负例 36 拆两 ID。**D 清单**：D1 双输出契约、D2 65535 负例、D3 SVCB RDATA、D4 非 2xx 头集合、D5 v1.1 口径清除、D6 §6.3.2 引证、D7 GET CL:0 改显式偏差声明、D8 Terminating 写死 FIN、D9 锚词注册钉死规则、D10 混合流 Content-Type 缺席断言改独立流（tshark 3.6.14 会话级泄漏实测）、D11 补 §2.3.4、D12 边界双变体拆原子例（TTL/QNAME/ID 各两例）。**双载体展开**：20 个 GET 变体（Question/Answer/RCODE/标志/负缓存/端口族）。计数 78 → **111（85 正 + 26 负）**；`doh_neg_carrier_port` 拆为 `doh_neg_layer_chain_missing_http`/`doh_neg_port_conflict`。
- v3.0.2（2026-09-01，复验修复轮）：rr-doh 二轮复验 22/24 CLOSED + 新 finding 逐项修复——**N1** 非默认端口断言 `tcp.dst_port`→`tcp.dstport`（3.6.14 实名）并补入 §1 字段白名单；**N2** 根名 GET b64 24→23 字符（17B≡2 恰为 23；24 是带 padding 的禁止形态）+ 删同形状重复例 doh_get_min_frame；**N3** AA=1 flags `84 00`→`85 80`（保留基线 RD=1/RA=1）；**C8** #1 补 `http.host=198.51.100.66` 默认断言；**N6** 配合设计除外条款（400 多参数正例编排）；**N7** rd_zero GET 改断言 fixture 预计算 b64 定值；**N8** §6 五层映射改 ID 引用（防重排错位）；**N11** ID 相邻值方向标注修正（1=最小+1、65534=最大-1）、soa 例载体列修复、余数例补 ANCOUNT=0 fixture 声明；**N12** svcb_alias 目标名根→svc.example.net（真实 AliasMode 形态，RDLENGTH 19）。计数 111→**110（84 正 + 26 负）**。
- v3.0.0（2026-09-01）：按《需求文档 v1.3》行为面全枚举重出（独立审查员 rr-doh：行为面约 135 点、实测复核全部 tshark 字段与"实测"声明）。38 条 → **78 条（56 正 + 22 负）**，新增「依据」列（RFC 优先）。扩面：非默认端口（25/26）、并发会话翻案（27）、base64url 余 1/余 2（28/29）、RCODE 值域 1/4/5/15（30–33）、RD=0/RA=0/AA=1（34–36）、ID/TTL/QNAME 相邻值（37–39，需求 v1.3 边界相邻值）、QTYPE TXT/MX/QCLASS CHAOS（40–42）、AAAA/CNAME 链/多答案/SVCB AnswerForm+AliasForm/TXT 串段答案（43–48）、SOA 负缓存（49）、Age 头（50）、混合 GET/POST 泄漏断言（51）、Host 显式（52）、400 多参数（53）、Accept 缺失（54）、Connection: close（55）、最小 GET（56）；负例 +8：65535 上界/Opcode/GET Content-Type/响应 QR/Z 位/RDLENGTH/ANCOUNT/QDCOUNT>1（71–78）；锚词改「主锚词（备选）」钉死。§1 改 v1.3 派生语言+三件套纪律+pcap/NIC 双输出；§6 五层映射重排；§8 三方一致性表重生成。设计配套升 v2.2.0（另行修订记录）。
- v2.0.1（2026-08-31）：按独立对抗审查 24 项问题清单修复（4C/5H/9M/6L），状态改为"修复完成，待原审查员复验关闭"。关键修复：①【C1】§1 字段清单与用例 5：`dns.count.auth_rrs`/`add_rrs` 改单数 `dns.count.auth_rr`/`add_rr`（`tshark -G fields` 实证只有单数）；②【C2】用例 9 根名断言 `dns.count.labels=0` 改 `=1`（实测 tshark 把根标签计为 1）；③【H3】packet_count 公式统一为 3+N+4（N=分段数）：单事务 8→**9**（旧"8=3+1+4"漏计响应分段）、用例 15 = 3+2N+4 → **13 = 7+2×3**、双流用例 14/22/23 = 9+9=**18**、用例 24 = **18**（第二会话握手包号 9→10）——以引擎 teardown 4 帧 + 同引擎 hls/http_flv 已实现用例实测（9/11/13/15 等差 2）为据；④【M1】用例 5 补 AA/TC/Z/NSCOUNT/ARCOUNT 断言（按 tshark 发射帧分布：TC/Z/COUNT 落请求帧、AA 落响应帧）；⑤【H2】用例 15 断言改"每笔请求均带 keep-alive、末笔按配置"（设计 §5 钉死策略）；⑥【H1】用例 18/19/20 与 `response.status` 非 2xx 通道对齐；⑦【M6】用例 23 标注 RFC 8484 §4.1 ID=0 SHOULD 与有意偏离；⑧【M8】用例 1 的 `http.content_length=33` 改 nonzero（精确值归用例 16 专断）；⑨【H5】§5 表补 `wire_fault` 注入口列（14 值与设计 §6/§7 枚举一一对应）；⑩【C4】§5 表并入 body_missing/http200_no_dns 分支锚词，14 行与设计 §7/§9 三方同序；⑪【M2】§6 与设计 §8 同步声明 65535 上界由实现校验、测试用 QNAME 255+MSS 分段代理；⑫【L6】§1 挥手 4 帧旁注"实现期校准值，非 RFC 消息数"；⑬用例 22 变体 A 长度修正 80→**81**（12+65+4，实测 http.content_length=81；含长度前缀与根标签）并按两变体建流改 18；⑭ §1 字段清单补 `dns.flags.authoritative`/`truncated`/`z`/`dns.count.labels`。