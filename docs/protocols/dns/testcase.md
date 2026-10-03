# #108 dns（域名系统）测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨批次二 as-built）
> 日期：2026-09-29
> 配套设计：`docs/protocols/dns/design.md` v1.0.0（D-DNS-1）
> 前序基线：**本协议无旧编号用例文档**（`docs/protocol-designs/` 无 `NN-dns-*`）；编号体系承 `docs/CODE_DESIGN.md` D-DNS-1 补遗的 **T-DNS-1…T-DNS-29**
> 机器契约：`trafficgen/test/protocol_pcap/cases/dns.json`（**29/29 ID 与本版 §2 一致，顺序一致，已机读实测**；**非负例顶层键零残留**，见 §1）
> 白话一句：**二十九条检查：二十三条看正常收发（一次问答、各种记录类型、别名链、否定应答、大响应协商、批量扫描、新网段），六条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **29 个唯一语义 ID：23 正 + 6 负**（负例 N-1…N-6）。派生规则：设计 §3 每个字段/编码条款、§5 每个派生规则、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-29 机读实测）**：

| 项 | 值 |
|---|---|
| 例数 | **29**（23 正 + 6 负） |
| 例顶层键 | 全 29 例含 `{expect,id,proto,spec_json,summary}`；追加 `strategy_fc` ×4（#3/#8/#9/#10）；追加**例级** `notes` ×14（#16–#20、#23–#29、#17）；追加 **`expect` 内** `notes` ×10（#1/#4/#5/#6/#7/#8/#9/#10/#14/#15） |
| **非负例 `spec_json` 顶层键** | **`{layers}` ×23（唯一键，零游离键、零顶层 `dns` 子映射、零顶层四元组、零 `count`）**——本协议**非负例零残留**，无 §1 迁移工作量（设计 §12.1） |
| 负例 `spec_json` 顶层键 | `{layers, dns}` ×1（#2，**presence 判死对象**）+ `{layers}` ×5 |
| 层形 | `[ip,udp,dns]` ×29（**统一三层，含 2 个 v6 例——v6 地址住 `layers[0].ip.{src,dst}`**） |
| 正例 `expect` | `packet_count` ×**4**（#1/#4/#7/#14）+ `min_packets` ×**19**；`fields` 全 23 例有（**共 88 条**）；`expect.notes` ×**10** + 例级 `notes` ×**14**（两处不同位置，见上行） |
| 负例 `expect` | **6/6 严格 `{expect_error, error_contains}`（无 `notes`，干净）** |

**输出契约（pcap/NIC 双输出）**：设计契约 = 两路径共用同一 cases JSON 与断言集（`udp.dstport`、`dns.*` 字段、`ipv6.version`），不设仅单路径可用的断言。**现状诚实标注**：存量 29 例 `nic_capture` 计数 = **0**——**今日只有 pcap 侧实证**，NIC 路径为设计契约尚未落地（P4 补 `nic_capture` 开关用例后方可声称双输出）。

**TSHARK 基线（本机 3.6.14，实测）**：`dns.*` 字段 **327 个**（`tshark -G fields | awk -F'\t' '$3 ~ /^dns\./'`）。本契约使用的字段通道：`dns.id`（**hex 形 `0x1234`**）、`dns.flags`（hex）、`dns.flags.response`/`recdesired`/`rcode`、`dns.count.queries`/`answers`/`auth_rr`/`add_rr`、`dns.qry.name`/`type`/`class`、`dns.resp.name`/`type`/`ttl`、`dns.a`/`aaaa`/`cname`/`ns`/`txt`/`ptr.domain_name`/`mx.preference`/`mx.mail_exchange`/`soa.mname`/`soa.rname`/`srv.*`/`ds.key_id`/`ds.algorithm`/`ds.digest_type`/`dnskey.protocol`/`dnskey.algorithm`/`naptr.*`、`ipv6.version`、`udp.dstport`。

**进制与聚合纪律（实测钉死，非臆造）**：① `dns.id` 是 **hex 字符串**（`0x1234` / `0x03e9`）；② `dns.flags`/`dns.qry.class` 是 hex；③ `dns.count.*`/`dns.qry.type`/`dns.resp.type`/`dns.resp.ttl`/`dns.mx.preference`/`dns.srv.port`/`dns.naptr.order` 是**十进制**；④ `dns.ds.key_id` 是 **hex**（`0x3039`）；⑤ **同名字段跨多 RR 用逗号聚合**（`dns.a=1.2.3.4,5.6.7.8`、`dns.qry.name=a.com,b.com`）——多答/多问例的断言值**必须是逗号拼接形**；⑥ `dns.resp.name` 在 CNAME 链中聚合两值（`www.example.com,alias.example.com`）。

**动态字段禁止硬编码**：生成期值用 `distinct_values`（集合比较，顺序无关）断言（#8/#9/#10）；`dns.id` 的 hex 形落盘已校准回钉（#10 的 notes 记载"先按十进制猜，错了回钉"）。

**包数约定（实测公式，设计 §9）**：单流 = `1 + (is_response ? 1 : 0)`。**无握手、无挥手、无 FIN/RST**（UDP 无连接）——**这是本协议与 tcp 族协议包数公式的最大差异**。负例无 `packet_count`（3 例在案 pcap 实测 0 帧）。

**保活/重试/RST 口径**：协议层**无保活**（无连接，正确）；**重传** = 客户端同 TxID 重发（#18 覆盖"同 ID 双包"）；RST 为 tcp 族概念，**本协议层不适用、不设断言**。

**断言强度基线（诚实标注）**：23 正例的 88 条字段断言**已逐条对实测 pcap 机读复核，0 失配**（设计 §0.1）。**但**：① 无任何 `frames` hex 断言（全部走 `dns.*` 字段通道，与 opcua 的"frames 为主"相反——DNS 的 tshark dissector 完备，字段通道更可靠）；② `dns_edns0`（#7）**只断言 1 条 `dns.qry.name`，未断言 EDNS0 是否生效 → 假绿**（**M-1**，设计 §9.2）。

## 2. 原子用例索引（29 ID = 23 正 + 6 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | 包数 | 断言条数 |
|---:|---|---|---|---:|---:|
| 1 | `dns_smoke_01` | 正 | §3.1/§3.3：单问基线（A，txid 默认 0x1234，QR=0 RD=1） | 1 | 8 |
| 2 | `dns_neg_flat` | 负 | §7 N-1：顶层 dns presence 判死 | — | 0 |
| 3 | `dns_neg_static_copy` | 负 | §7 N-2：静态复制拒 | — | 0 |
| 4 | `dns_aaaa` | 正 | §3.3：QTYPE=28 | 1 | 3 |
| 5 | `dns_response` | 正 | §3.1/§3.4：响应包（txid 回显 + A RDATA） | 2 | 3 |
| 6 | `dns_nxdomain_soa` | 正 | §3.4/§3.5：rcode=3 + authority SOA | 2 | 1 |
| 7 | `dns_edns0` | 正 | §3.7：EDNS0 OPT（**M-1 未生效**） | 1 | 1 |
| 8 | `dns_name_dynamic` | 正 | §12：`name` list 动态（flows=2） | 2 | 1 |
| 9 | `dns_qtype_dynamic` | 正 | §12：`query_type` inc 动态（1→28） | 2 | 1 |
| 10 | `dns_txid_dynamic` | 正 | §12：`txid` inc 动态（1000→1001） | 2 | 1 |
| 11 | `dns_neg_tcp` | 负 | §7 N-3：transport=tcp 链上拒 | — | 0 |
| 12 | `dns_neg_rcode` | 负 | §7 N-4：rcode=16 越界 | — | 0 |
| 13 | `dns_neg_empty_name` | 负 | §7 N-5：空域名 | — | 0 |
| 14 | `dns_multi_question` | 正 | §3.3：QDCOUNT=2 | 1 | 3 |
| 15 | `dns_multi_answer` | 正 | §3.4：ANCOUNT=2（多 A） | 2 | 2 |
| 16 | `dns_cname_chain` | 正 | §3.5：CNAME + A 别名链 | 2 | 3 |
| 17 | `dns_neg_long_domain` | 负 | §7 N-6：单 label 64B 超限 | — | 0 |
| 18 | `dns_retry_same_txid` | 正 | §5：固定 txid 1001 双包同 ID | 2 | 2 |
| 19 | `dns_v6_query` | 正 | §2/§4：IPv6 承载查询（offset 62） | 1 | 2 |
| 20 | `dns_aaaa_response` | 正 | §3.5：AAAA 问答配对 | 2 | 6 |
| 21 | `dns_mx_response` | 正 | §3.5：MX（preference + exchange） | 2 | 7 |
| 22 | `dns_txt_response` | 正 | §3.5：TXT | 2 | 6 |
| 23 | `dns_ns_response` | 正 | §3.5：NS（委派链） | 2 | 6 |
| 24 | `dns_ptr_response` | 正 | §3.5：PTR（`in-addr.arpa` 反向） | 2 | 6 |
| 25 | `dns_srv_response` | 正 | §3.5：SRV（priority/weight/port/target） | 2 | 9 |
| 26 | `dns_v6_aaaa_response` | 正 | §2/§3.5：v6 承载 AAAA 问答 | 2 | 5 |
| 27 | `dns_ds_response` | 正 | §3.5：DS（digest hex） | 2 | 4 |
| 28 | `dns_dnskey_response` | 正 | §3.5：DNSKEY（public_key base64） | 2 | 4 |
| 29 | `dns_naptr_response` | 正 | §3.5：NAPTR | 2 | 4 |

**T-编号对照**：`dns_smoke_01` ≡ T-DNS-1；`dns_neg_flat` ≡ T-DNS-2；`dns_neg_static_copy` ≡ T-DNS-3；`dns_aaaa` ≡ T-DNS-4；`dns_response` ≡ T-DNS-5；`dns_nxdomain_soa` ≡ T-DNS-6；`dns_edns0` ≡ T-DNS-7；`dns_name_dynamic` ≡ T-DNS-8；`dns_qtype_dynamic` ≡ T-DNS-9；`dns_txid_dynamic` ≡ T-DNS-10；`dns_neg_tcp` ≡ T-DNS-11；`dns_neg_rcode` ≡ T-DNS-12；`dns_neg_empty_name` ≡ T-DNS-13；`dns_multi_question` ≡ T-DNS-14；`dns_multi_answer` ≡ T-DNS-15；`dns_cname_chain` ≡ T-DNS-16；`dns_neg_long_domain` ≡ T-DNS-17；`dns_retry_same_txid` ≡ T-DNS-18；`dns_v6_query` ≡ T-DNS-19；`dns_aaaa_response` ≡ T-DNS-20；`dns_mx_response` ≡ T-DNS-21；`dns_txt_response` ≡ T-DNS-22；`dns_ns_response` ≡ T-DNS-23；`dns_ptr_response` ≡ T-DNS-24；`dns_srv_response` ≡ T-DNS-25；`dns_v6_aaaa_response` ≡ T-DNS-26；`dns_ds_response` ≡ T-DNS-27；`dns_dnskey_response` ≡ T-DNS-28；`dns_naptr_response` ≡ T-DNS-29。**序号以 cases JSON 顺序为权威**（JSON 中 #2/#3 为负例，与 T 编号文档序一致；#14.. 起编号连续）。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `packet_count`/`min_packets` + `fields`；字段值与帧位由实测 pcap 双向确认（**88/88 实测 0 失配**）。

### 3.1 `dns_smoke_01`（1 包）

`ip{src:10.0.0.1, dst:20.0.0.1}`、`udp{src_port:12345, dst_port:53}`、`dns{name:"example.com", query_type:1}`。

- `packet_count=1`；8 条断言：`udp.dstport=53`、`dns.id=0x1234`、`dns.flags=0x0100`、`dns.flags.response=0`、`dns.flags.recdesired=1`、`dns.qry.name=example.com`、`dns.qry.type=1`、`dns.qry.class=0x0001`。
- **线证据（实测）**：UDP payload 起点 = **offset 42**（IPv4 14+20+8）；payload hex = `1234 0100 0001 0000 0000 0000 07'example' 03'com' 00 0001 0001`（**29B**）；以太帧 **71B**。
- **头三常量证据**：`dns.id` 默认 0x1234（`buildDNSQuery:379-381` 回退）；`dns.flags=0x0100` = QR=0 / Opcode=0 / RD=1；`QDCOUNT=1`。

### 3.2 `dns_aaaa`（1 包）

`dns{name:"example.com", query_type:28}`。

- `packet_count=1`；3 条：`udp.dstport=53`、`dns.qry.name=example.com`、`dns.qry.type=28`。
- **与 #1 的差异仅是 QTYPE**（实测 payload 尾 `0000 1c 0001` vs `0000 01 0001`）——**QTYPE 是唯一变量**，这是 AAAA 覆盖的原子性证据。

### 3.3 `dns_response`（2 包）

`dns{name:"example.com", query_type:1, is_response:true, response_ip:"1.2.3.4"}`。

- `min_packets=2`；3 条：帧 1 `dns.flags.response=0`、帧 2 `dns.flags.response=1`、帧 2 `dns.a=1.2.3.4`。
- **实测帧 2**：`dns.id=0x1234`（**与帧 1 同值 → TxID 回显 MUST**，RFC 1035 §4.1.1）、`dns.flags=0x8180`（QR=1/RD=1/RA=1/rcode=0）、`dns.count.answers=1`、`dns.resp.name=example.com`、`dns.resp.type=1`、`dns.resp.ttl=300`（legacy 单 RR 路径硬写 300，`buildDNSResponse:447`）；以太帧 **98B**。
- **TxID 回显的双向证据**：#18 固定 txid 时两帧同 `0x03e9`（非默认值也回显），本例默认值也回显。

### 3.4 `dns_nxdomain_soa`（2 包）

`dns{name:"example.com", query_type:1, is_response:true, response_code:3, authority:[{name:"example.com", type:6, mname:"ns.example.com", rname:"hostmaster.example.com", serial:1, refresh:3600, retry:600, expire:86400, minimum:300}]}`。

- `min_packets=2`；1 条：帧 2 `dns.flags.rcode=3`。
- **实测帧 2**：`dns.flags=0x8183`（低 4 位 = 3）、`dns.count.answers=0`、**`dns.count.auth_rr=1`**、`dns.resp.type=6`（SOA）、`dns.soa.mname=ns.example.com`、`dns.soa.rname=hostmaster.example.com`；以太帧 **154B**。
- **负缓存证据**：ANCOUNT=0 + NSCOUNT=1 —— **答案段空、权威段带 SOA**，这正是 RFC 1035 §6.2.5 的 NXDOMAIN 负缓存形态（与"答案段有 SOA"不同）。**本用例只断言 rcode=3**，NSCOUNT/SOA 字段为**可收编的补充断言**（A′）。

### 3.5 `dns_edns0`（1 包）——**M-1 假绿，本契约如实登记**

`dns{name:"example.com", query_type:1, edns0_enabled:true}`。

- `packet_count=1`；**1 条**：`dns.qry.name=example.com`。
- **实测与设计不符（M-1）**：帧 1 `dns.count.add_rr=**0**`、`dns.flags=0x0100`、以太帧 **71B**、UDP payload **与 `dns_smoke_01` 逐字节相同**——**EDNS0 未生效**。
- 根因：层 schema `udp_payload_size` 默认 0 → 单问路径 `buildDNSQueryWithEDNS0:606-608` 早退（设计 §9.2 M-1）。
- **该例 `summary` 声称 "edns0_enabled→附加节ARCOUNT=1" 与实测相反**；`notes` 称 "RFC 6891 OPT" 亦不成立。**本契约不为此背书**——按 cases JSON 现状如实登记为**假绿**，P4 必须：①修早退条件；②补 `dns.count.add_rr=1` 断言；③重跑后钉（帧长 71→82，`packet_count` 不变）。
- **对照组（本车道实测，非用例）**：多问路径 + `edns0_enabled:true`（`udp_payload_size` 缺席）→ **ARCOUNT=1、OPT 落线、DNS 34B**（`optWireRR` 的 size=0 → 4096 回退）——**同一配置两条路径行为分叉**，这是 M-1 的直接证据。

### 3.6 `dns_name_dynamic`（2 包）

`dns{name:{strategy:"list", list:["a.com","b.com"]}, query_type:1}` + `strategy_fc{type:"flows", value:2}`。

- `min_packets=2`；1 条：`dns.qry.name` **`distinct_values:["a.com","b.com"]`**（集合比较，顺序无关）。
- **实测**：帧 1 `dns.qry.name=a.com`、帧 2 `=b.com`；两帧以太长均 **65B**（DNS 23B：`01'a'03'com'00` = 7B + 4 + 12）。
- **动态生效证据**：两流域名不同 → `layer_dyn.go` 的 `dns.name` string 面（`list` 策略）按 `FlowIndex` 直解生效（`chain_planner_translate.go:1971`）。

### 3.7 `dns_qtype_dynamic`（2 包）

`dns{name:"example.com", query_type:{strategy:"inc", range:[1,28], step:27}}` + `strategy_fc{flows:2}`。

- `min_packets=2`；1 条：`dns.qry.type` **`distinct_values:["1","28"]`**（**字符串形**，与实测 `dns.qry.type` 为十进制串一致）。
- **实测**：帧 1 `dns.qry.type=1`、帧 2 `=28`。
- **int 面证据**：`inc` 策略在 `query_type` 上生效（`layer_dyn.go` 的 int 面）。

### 3.8 `dns_txid_dynamic`（2 包）

`dns{name:"example.com", query_type:1, txid:{strategy:"inc", range:[1000,1001]}}` + `strategy_fc{flows:2}`。

- `min_packets=2`；1 条：`dns.id` **`distinct_values:["0x03e8","0x03e9"]`**（**hex 形**）。
- **实测**：帧 1 `dns.id=0x03e8`（1000）、帧 2 `=0x03e9`（1001）。
- **进制教训（notes 原文记载）**："txid 1000=0x03e8/1001=0x03e9 hex形落盘校准回钉（**先按十进制猜，错了回钉**）"——**tshark 的 `dns.id` 是 hex 串，不是十进制**；这是本协议最容易写错的断言。

### 3.9 `dns_multi_question`（1 包）

`dns{questions:[{name:"a.com", type:1}, {name:"b.com", type:28}]}`（**无 `name`/`query_type`**——`questions` 覆盖之）。

- `packet_count=1`；3 条：`dns.count.queries=2`、`dns.qry.name=`**`a.com,b.com`**（逗号聚合）、`dns.qry.type=`**`1,28`**（逗号聚合）。
- **实测**：UDP payload **34B**、以太帧 **76B**；两问**同一帧**（QDCOUNT=2）——**多问不是多帧**。
- **class 缺省证据**：两问均未写 `class` → 实测 `dns.qry.class=0x0001,0x0001`（IN 缺省生效）。

### 3.10 `dns_multi_answer`（2 包）

`dns{name:"example.com", query_type:1, is_response:true, answers:[{name:"example.com", type:1, ip:"1.2.3.4"}, {name:"example.com", type:1, ip:"5.6.7.8"}]}`。

- `min_packets=2`；2 条：帧 2 `dns.count.answers=2`、帧 2 `dns.a=`**`1.2.3.4,5.6.7.8`**。
- **实测帧 2**：`dns.resp.name=example.com,example.com`（**同一域名写两遍——无压缩**，G-DNS-1 的直接证据）、`dns.resp.type=1,1`、`dns.resp.ttl=300,300`；以太帧 **125B**。
- **多 RR 单帧证据**：ANCOUNT=2 在一帧内。

### 3.11 `dns_cname_chain`（2 包）

`dns{name:"www.example.com", query_type:1, is_response:true, answers:[{name:"www.example.com", type:5, target:"alias.example.com"}, {name:"alias.example.com", type:1, ip:"1.2.3.4"}]}`。

- `min_packets=2`；3 条：帧 2 `dns.count.answers=2`、帧 2 `dns.a=1.2.3.4`、帧 2 `dns.cname=alias.example.com`。
- **实测帧 2**：`dns.resp.name=www.example.com,alias.example.com`、`dns.resp.type=5,1`（**CNAME 在前、A 在后**，别名链顺序）；以太帧 **154B**。
- **RDATA 分派证据**：同一响应的两个 RR 走不同 `encodeRDATA` 分支（TypeCNAME → 域名；TypeA → 4B IP）。

### 3.12 `dns_retry_same_txid`（2 包）

`dns{name:"example.com", query_type:1, txid:1001, is_response:true, response_ip:"1.2.3.4"}`。

- `min_packets=2`；2 条：帧 1 `dns.id=0x03e9`、帧 2 `dns.id=0x03e9`（**两帧同 ID**）。
- **与 #5 的差异仅是 txid 固定**：#5 是默认 0x1234 回显、本例是**非默认值 1001 也回显**——**两条合起来证明"回显的是配置值而非硬编码默认"**。
- **重传语义**：UDP 丢包后客户端同 TxID 重发（RFC 1035 §4.1.1 的 ID 用途）；本例钉"重传不变"。

### 3.13 `dns_v6_query`（1 包）

`ip{src:"fd00::1", dst:"fd00::2"}`、`udp{src_port:12345, dst_port:53}`、`dns{name:"example.com", query_type:28}`。

- `min_packets=1`；2 条：`ipv6.version=6`、`dns.qry.type=28`。
- **协议与地址族解耦证据**：DNS payload **与 #4 逐字节相同（29B）**，只有**起点从 offset 42 变 62**（IPv6 14+40+8）；以太帧 71B → **91B**（+20 = IPv6 头增量）。
- **口径注**：UDP 无握手，**首帧即数据帧**（与 tcp 族 v6 例"帧 4 起"不同）——v6 承载的首帧断言是正确口径。

### 3.14 `dns_aaaa_response`（2 包）

`dns{name:"example.com", query_type:28, is_response:true, response_ip:"2001:db8::1"}`。

- `min_packets=2`；6 条：帧 1 `dns.qry.name=example.com`、帧 1 `dns.qry.type=28`、帧 2 `dns.resp.name=example.com`、帧 2 `dns.resp.type=28`、帧 2 `dns.count.answers=1`、帧 2 `dns.aaaa=2001:db8::1`。
- **问答配对断言面**：帧 1 问 + 帧 2 答的 name/type **双向对齐**（这是"配对"而非"只看答"的证据）。
- **RDATA 长度证据**：AAAA RDATA **恒 16B**（`encodeRDATA:863-868`）；以太帧 110B（vs #5 的 98B，差 12 = 16−4）。

### 3.15 `dns_mx_response`（2 包）

`dns{name:"example.com", query_type:15, is_response:true, answers:[{name:"example.com", type:15, preference:10, target:"mail.example.com"}]}`。

- `min_packets=2`；7 条：`dns.qry.name`/`dns.qry.type=15`（帧 1）、`dns.resp.name`/`dns.resp.type=15`/`dns.count.answers=1`/`dns.mx.preference=10`/`dns.mx.mail_exchange=mail.example.com`（帧 2）。
- **RDATA 结构证据**：`dns.mx.preference`（2B）+ `dns.mx.mail_exchange`（域名）**两个字段都断言**——证明 RDATA = `2B preference + 域名`（`encodeRDATA:875-882`），而非只有一个域名。

### 3.16 `dns_txt_response`（2 包）

`dns{name:"example.com", query_type:16, is_response:true, answers:[{name:"example.com", type:16, text:"hello-world"}]}`。

- `min_packets=2`；6 条：帧 1 `dns.qry.name`/`dns.qry.type=16`；帧 2 `dns.resp.name`/`dns.resp.type=16`/`dns.count.answers=1`/`dns.txt=hello-world`。
- **character-string 证据**：`dns.txt` 解出**不带长度前缀的原文**（tshark 剥离 1B 长度）——断言值 `hello-world` 即"长度前缀 + 11 字节"的语义结果。

### 3.17 `dns_ns_response`（2 包）

`dns{name:"example.com", query_type:2, is_response:true, answers:[{name:"example.com", type:2, target:"ns1.example.com"}]}`。

- `min_packets=2`；6 条：`dns.qry.name`/`dns.qry.type=2`（帧 1）、`dns.resp.name`/`dns.resp.type=2`/`dns.count.answers=1`/`dns.ns=ns1.example.com`（帧 2）。
- **与 #16 的差异**：NS 与 CNAME 同走 `case TypeCNAME, TypeNS, TypePTR` 的域名分支（`encodeRDATA:869-874`）——**同一代码分支的三协议各一例**（NS=#23 / CNAME=#16 / PTR=#24），这是"分支级"而非"类型级"覆盖的证据。

### 3.18 `dns_ptr_response`（2 包）

`dns{name:"1.0.0.10.in-addr.arpa", query_type:12, is_response:true, answers:[{name:"1.0.0.10.in-addr.arpa", type:12, target:"host.example.com"}]}`。

- `min_packets=2`；6 条：`dns.qry.name=1.0.0.10.in-addr.arpa`/`dns.qry.type=12`（帧 1）、`dns.resp.name=1.0.0.10.in-addr.arpa`/`dns.resp.type=12`/`dns.count.answers=1`/`dns.ptr.domain_name=host.example.com`（帧 2）。
- **反向域名编码证据**：`1.0.0.10.in-addr.arpa` 是 **5 个 label**（`1`/`0`/`0`/`10`/`in-addr`/`arpa` → 实为 6 段），实测以太帧 **81B**（查询，DNS 39B）——**长 label 链**的编码正确性。

### 3.19 `dns_srv_response`（2 包）

`dns{name:"_sip._tcp.example.com", query_type:33, is_response:true, answers:[{name:"_sip._tcp.example.com", type:33, priority:10, weight:20, port:5060, target:"sip.example.com"}]}`。

- `min_packets=2`；**9 条（全协议最多）**：帧 1 `dns.qry.name=_sip._tcp.example.com`/`dns.qry.type=33`；帧 2 `dns.srv.service=_sip`、`dns.srv.proto=_tcp`、`dns.srv.name=example.com`、`dns.resp.type=33`、`dns.count.answers=1`、`dns.srv.port=5060`、`dns.srv.target=sip.example.com`。
- **服务发现语义证据**：`dns.srv.service`/`proto`/`name` 三字段由 tshark **从 QNAME 的前导下划线 label 拆解**得出（`_sip` + `_tcp` + `example.com`）——**这是"域名结构语义"的断言，不是报文新增字段**。
- **RDATA 四字段证据**：`priority`(2B) + `weight`(2B) + `port`(2B) + `target`(域名)，`dns.srv.port=5060` 与 `dns.srv.target` 都断言（`encodeRDATA:916-929`）。

### 3.20 `dns_v6_aaaa_response`（2 包）

`ip{src:"fd00::1", dst:"fd00::2"}`、`dns{name:"example.com", query_type:28, is_response:true, response_ip:"2001:db8::1"}`。

- `min_packets=2`；5 条：帧 1 `ipv6.version=6`/`dns.qry.type=28`；帧 2 `ipv6.version=6`/`dns.resp.type=28`/`dns.aaaa=2001:db8::1`。
- **与 #20 的差异仅是承载**：DNS payload 与 #20 相同，两帧以太长 +20（IPv6 头）——**v6 承载不改协议语义**的直接证据。

### 3.21 `dns_ds_response`（2 包）

`dns{name:"example.com", query_type:43, is_response:true, answers:[{name:"example.com", type:43, key_tag:12345, algorithm:8, digest_type:2, digest:"AABBCCDDEE"}]}`。

- `min_packets=2`；4 条：帧 1 `dns.qry.type=43`；帧 2 `dns.resp.type=43`/`dns.count.answers=1`/`dns.ds.key_id=**0x3039**`（**hex 形**；12345 = 0x3039）。
- **hex 解码证据**：`digest:"AABBCCDDEE"` 是**hex 字符串**（5 字节），经 `hex.DecodeString` 落为 5B RDATA（`encodeRDATA:953-956`）→ RDLENGTH = 4 + 5 = **9**；以太帧 103B。
- **进制教训**：`dns.ds.key_id` 是 **hex**（`0x3039`），与 `dns.ds.algorithm`（十进制 `8`）**不同进制**——同 RR 内混进制是 tshark 的字段定义，不是实现选择。

### 3.22 `dns_dnskey_response`（2 包）

`dns{name:"example.com", query_type:48, is_response:true, answers:[{name:"example.com", type:48, key_flags:256, protocol:3, algorithm:8, public_key:"AQAB"}]}`。

- `min_packets=2`；4 条：帧 1 `dns.qry.type=48`；帧 2 `dns.resp.type=48`/`dns.count.answers=1`/`dns.dnskey.protocol=3`。
- **base64 解码证据**：`public_key:"AQAB"` 是 **base64**（解码 3 字节），经 `base64.StdEncoding.DecodeString` 落为 3B RDATA（`encodeRDATA:967-970`）→ RDLENGTH = 4 + 3 = **7**；以太帧 101B。
- **与 #27 的编码差异**：DS 用 **hex**、DNSKEY 用 **base64** —— 两条用例正是"两种编码变体各一例"（§4 数据场景层要求）。

### 3.23 `dns_naptr_response`（2 包）

`dns{name:"example.com", query_type:35, is_response:true, answers:[{name:"example.com", type:35, order:100, preference:50, flags:"S", service:"sip+E2U", regexp:"!^.*$!sip:info@example.com!", target:"_sip._tcp.example.com"}]}`。

- `min_packets=2`；4 条：帧 1 `dns.qry.type=35`；帧 2 `dns.resp.type=35`/`dns.count.answers=1`/`dns.naptr.order=100`。
- **实测帧 2 全字段**：`dns.naptr.order=100`、`dns.naptr.preference=50`、`dns.naptr.flags=S`、`dns.naptr.service=sip+E2U`、`dns.naptr.replacement=_sip._tcp.example.com`；以太帧 **159B**（**全协议最大帧**，DNS 117B）。
- **三 character-string 证据**：`flags`/`service`/`regexp` 各为 1B 长度前缀 + 内容（`appendCharString:984-992`），其中 `regexp` 含 `!`/`$`/`@`/`:` 等特殊字符**原样落线**（无转义）——`dns.naptr.service=sip+E2U` 的 `+` 亦原样。
- **本用例只断言 `order`**，其余四字段为**可收编的补充断言**（A′）。

**正例总则**：多问一帧、多答一帧、多 RR 响应、别名链、v6 承载、动态多流均为正例形态；只有配置/长度/载体错误进入负例。

## 4. 负例契约

负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 UDP 外壳的假成功（**3 例在案 pcap 实测均 0 帧**，文件名 `<id>.neg.pcap`）。锚词与设计 §7 表一一对应、同序：

| # | ID | 故障输入（机读实测） | JSON `error_contains` | 代码文案（逐字） | 代码行 | 拒绝层 |
|---:|---|---|---|---|---|---|
| N-1 | `dns_neg_flat` | `{layers:[…{dns:{}}], dns:{}}`（**空 map 也死**） | `no longer accepts a top-level dns sub-config` | `protocol dns no longer accepts a top-level dns sub-config (move it into the dns layer of an [ip,udp,dns] layers chain)` | `strategy_convert.go:8650-8654` | CheckProtoFlat（schema 400） |
| N-2 | `dns_neg_static_copy` | `flows=2` + 全静态四元组 | `static four-tuple` | `layers pin a static four-tuple but flows > 1` | 静态复制门 | ValidateLayers |
| N-3 | `dns_neg_tcp` | 层内 `transport:"tcp"` | `tcp transport not supported` | `dns: tcp transport not supported by the layer chain yet (udp only; tcp deferred)` | `layer_gen.go:114` | 层校验器 |
| N-4 | `dns_neg_rcode` | `response_code:16`（4 位上限 15） | `out of range [0,15]` | `layers: layer "dns" field "response_code" = 16 invalid: out of range [0,15]` | `complete.go:325`（V9 范围门） | ValidateLayers |
| N-5 | `dns_neg_empty_name` | `name:""`（无 `questions`） | `query_name (domain) is required` | `dns query_name (domain) is required` | `dns.go:133` | 层校验器 |
| N-6 | `dns_neg_long_domain` | 单 label 64 字节（>63） | `exceeds max 63 octets` | `dns query name label "aaa…" exceeds max 63 octets (RFC 1035 §3.1)` | `dns.go:118` | 层校验器 |

**锚词口径**：`error_contains` 是**子串**判定，6/6 均命中代码文案（N-1 含前缀 `protocol `、N-3/N-5/N-6 含前缀 `dns `、N-4 含前缀 `layers: layer "dns" `）。

**锚词来源三分（重要，防误判）**：

| 来源 | 负例 | 说明 |
|---|---|---|
| **框架 schema/V9 门** | N-1（CheckProtoFlat）、N-2（静态复制门）、N-4（V9 范围门） | **不经过 `dns.go`**；N-4 尤其注意——`dns.go:104` 的 `dns rcode %d exceeds the 4-bit field (max 15)` **不可达**（V9 先拒），两者**语义重复但字面不同**（G-DNS-7） |
| **层校验器（`dns.go`）** | N-5、N-6 | 经 `RegisterLayerValidator`（`layer_gen.go:106`）→ `validateDNSConfig` |
| **链上载体门（`layer_gen.go`）** | N-3 | 层校验器内的载体拒绝（先于 `validateDNSConfig` 的 transport 枚举，两者都拒 tcp 但字面不同） |

**负例原子性**：每例单一故障注入；单次执行不得混注（6/6 机读实测均单注入）。

**负例纯净性**：6/6 `expect` 键集合**严格 = `{expect_error, error_contains}`**（**无 `notes`、无 `packet_count`、无 `fields`**）——符合 §7 负例纪律。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：

| 分支 | 锚词 | 代码行 | 今日可达性（**本车道代码探针实测**） |
|---|---|---|---|
| transport 非法值 | `dns transport %q not supported (allowed: udp, tcp)` | `dns.go:98` | **可达**（实测 `transport:"sctp"` 命中） |
| rcode > 15（planner 侧） | `dns rcode %d exceeds the 4-bit field (max 15)` | `dns.go:104` | **不可达**（V9 门先拒，见 N-4） |
| Questions[i] 空名 | `dns questions[%d]: name is required` | `dns.go:129` | **可达**（实测命中） |
| A/AAAA RR 族不匹配（answers） | `dns answers[%d]: TypeA requires an IPv4 ip` | `dns.go:189` | **可达**（实测命中） |
| A/AAAA RR 族不匹配（authority） | `dns authority[%d]: …` | `dns.go:189` | 同代码路径（未单测） |
| ResponseIP 非法 IP | `dns response_ip %q is not a valid IP address` | `dns.go:159` | legacy 单 RR 路径可达 |
| ResponseIP 族不匹配（TypeA） | `dns TypeA (A record) requires an IPv4 response_ip` | `dns.go:162` | **可达**（实测命中） |
| ResponseIP 族不匹配（TypeAAAA） | `dns TypeAAAA (AAAA record) requires an IPv6 response_ip` | `dns.go:165` | **可达**（实测命中） |
| 全名 > 253 | `exceeds max 253 characters` | `dns.go:114` | **可达**（实测 **254 拒 / 253 放**——边界两侧均实测） |
| DNSConfig 为 nil | `DNS config is required` | `dns.go:90` | 链路径不可达（translate 恒建非 nil）；legacy 路径可达 |

**未入用例的静默路径（缺陷候选）**：① DS `Digest` 非 hex / DNSKEY `PublicKey` 非 base64 → **静默产空 RDATA**（`dns.go:953-956`/`967-970`，G-DNS-5）；② **EDNS0 单问 + size 缺席 → 静默不发 OPT**（M-1）。

## 5. 覆盖与对账

### 5.1 三源回指行

RFC 1035/6891/4033/4034/3596/2782/3401/7766（设计 §10）+ D-DNS-1（设计 §11）+ tshark 3.6.14 字段表（327 字段）与 **29 例实测 pcap**（`/tmp/mcp-pcaps/dns/`）→ 29 ID（本契约 §2）。第三源"已确认现网行为"当前 = **抓包级已到**（本仓引擎产出的 23 例正例 pcap 逐字段核对，**88 条断言 0 失配**），但**真实解析器/开源实现的线字节未取到** → G-DNS-11（按 §5.5 不写死进实现）。

**29 ID 逐项回指（§9.5 要求）**：#1←设计 §3.1/§3.3；#2←§7 N-1；#3←§7 N-2；#4←§3.3；#5←§3.1/§3.4；#6←§3.4/§3.5；#7←§3.7（**M-1**）；#8/#9/#10←§12；#11←§7 N-3；#12←§7 N-4；#13←§7 N-5；#14←§3.3；#15←§3.4；#16←§3.5；#17←§7 N-6；#18←§5；#19←§2/§4；#20..#29←§3.5。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 1035/6891/4033/4034/3596/2782/3401/7766 公开语义 + D-DNS-1 内部契约 + 仓库落码反推 + tshark 3.6.14 字段与 pcap 实测**，**非纯规范反推**（RFC 逐条条款号未全部标注到行 → G-DNS-11）。
- **对账两行（逐表重数，机读复算，不做跨表二次加总）**：**要求逻辑点总数 = 79**（八项 8 行 + 矩阵 24 格 + 变体 26 行 + 商业映射 21 行）；**已覆 = 47**；**立项/待修 = 14**；**不适用 = 18**。47 + 14 + 18 = 79 ✓
  **逐表重数（每表脚注同值，机读复算）**：§10.1 八项（8 = 覆 1 + 立项 4 + 不适用 3）/ §10.2 消息×终态（24 = 覆 14 + 立项 1【M-1】+ 不适用 9）/ §10.3 变体（26 = 覆 18 + 立项 8【含 M-1 的 2 行】+ 不适用 0）/ §10.4 商业映射（21 = 覆 14 + 立项 1【M-1】+ 不适用 6）。
  **粒度声明**：行/格粒度每点 1 计；M-1 与 G-DNS-1…G-DNS-16 不折进 79。**反查全绿 ≠ 覆盖全**。**逐表脚注见设计 §10.1–§10.4**。
- **门3 抽查候选**：最复杂用例 = **#25 `dns_srv_response`**（9 条断言：帧 1 的 qry.name/qry.type + 帧 2 的 srv.service/proto/name + resp.type + count.answers + srv.port/target；交织维度 = QNAME 结构语义(3) × RDATA 字段(4) × 问答配对(2)）；**建议门3 抽 #25 + #29**（`dns_naptr_response` 补最大帧 159B + 三 character-string 面）。

### 5.3 T-编号与 id 对照

见 §2 末表（29/29 一一对应，T-DNS-1…T-DNS-29）。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | DNS 无连接；单次查询可带可选响应，重复事务走独立 `flows` | **沿用 G-DNS-2**：若支持同流多轮，需在 TCP 载体接线时新增显式事务序列；当前不声称覆盖 |
| ② | 非正常结束 | UDP 无 FIN/RST；NXDOMAIN 是正常响应，不是异常结束 | **不适用**（UDP 无连接释放；#6 覆盖否定应答） |
| ③ | 长保活 | UDP 无连接保活 | **不适用**（无保活状态；#18 覆盖客户端重传） |

### 6.2 A′/B′ 两分类表

**A′（P4 接线，17 例候选，设计 §13；每项均有明确缺口编号）**：

| 类 | 内容 | 落点 |
|---|---|---|
| **M-1 修复面** | ①改 `buildDNSQueryWithEDNS0` 早退条件；②**#7 补 `dns.count.add_rr=1` 断言**；③重跑后钉（帧长 71→82） | 设计 §9.2 |
| 拒绝分支面 | transport 非法值 / questions[i] 空名 / RR 族不匹配（answers+authority）/ ResponseIP 族不匹配（TypeA+TypeAAAA）/ 全名 254 | 设计 §7 表 |
| EDNS0 面 | `dns_edns0_size0_multiq`（多问 + size 缺席 → OPT 落线，**M-1 对照组**）/ `dns_edns0_dnssec_do`（DO 位断言） | 设计 §10.3 行 22 |
| 数据形态面 | 未知 QTYPE（→RDLEN=0）/ 非 IN QCLASS / 空名 RR（→0x00）/ 尾点 FQDN / 连续点空 label | 设计 §10.3 行 14/16/23/24/25 |
| 编码吞错面 | DS digest 非 hex / DNSKEY key 非 base64（静默空 RDATA） | G-DNS-5 |
| 端口面 | `dst_port` 缺省补齐 53 | 设计 §8 |
| 地址族面 | 异族混写拒绝 | 设计 §8 |
| 断言增强面 | #6 补 NSCOUNT/SOA 字段；#25/#29 补全字段（service/proto/name/weight/target；preference/flags/service/replacement） | 本契约 §3.4/§3.19/§3.23 |
| NIC 面 | 补 `nic_capture` 开关用例（今日零） | 本契约 §1 |
| name 压缩面 | 实现压缩（省 13B/RR）或明确不解决 | G-DNS-1 |
| TCP 载体面 | 接线 TCPGenerator 全握手或明确不解决 | G-DNS-2 |
| DoT 面 | tls 载体接线 | G-DNS-3 |

### 6.3 3.14 豁免边界审计

**无长连接载体（UDP）→ `sessions[]` 豁免**（设计 §12.3 会话表：DNS 无连接概念）；多流并发由策略级 `flows`（`strategy_fc`）承载（#8/#9/#10）；**单包多载荷** = **适用**（#14 单帧 QDCOUNT=2、#15 单帧 ANCOUNT=2）——**与 opcua 的“不适用”相反，DNS 原生支持单消息多问题/多 RR**。

## 7. 实现后执行建议

1. **P4 顺序**：①**先修 M-1**（`buildDNSQueryWithEDNS0` 早退条件 + #7 补 `add_rr` 断言），重跑后钉（帧长 71→82）；②补 A′ 拒绝分支例（10 条）；③补数据形态例（5 条）；④补断言增强（#6/#25/#29 字段）；⑤补 NIC 用例；⑥全量复跑。**本协议无 §1 迁移步骤**（非负例顶层零残留）。
2. **实测顺序**：先 #1（头三常量 0x1234/0x0100/QDCOUNT=1，payload 29B @offset 42），再 #5（响应 0x8180 + TxID 回显 + A RDATA），再 #14（多问 QDCOUNT=2 + 逗号聚合），再 #6（NXDOMAIN NSCOUNT=1），最后 #25（SRV 9 断言）、#29（NAPTR 159B 最大帧）、#19/#26（v6 offset 62）。
3. **进制纪律（本协议高频错点）**：`dns.id` **hex**（`0x1234`/`0x03e9`）；`dns.ds.key_id` **hex**（`0x3039`）；`dns.qry.class` **hex**（`0x0001`）；其余计数/类型/端口/TTL **十进制**；多值字段 **逗号聚合**。**断言前先 `tshark -r <pcap> -T fields -e <field>` 落盘校准，不许凭字段名猜格式**（#10 的 notes 记载了"先按十进制猜，错了回钉"的教训）。
4. 二进制与 HEAD 同代确认（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=dns` 全量不是增量）；门2④ 反查绿后进 P6。
5. 任何 RFC 条款号的具体引用须有规范原文证据（G-DNS-11 纪律）。

## 8. 存量审计（29 例逐条去向）

### 8.1 存量实测面（2026-09-29）

`cases/dns.json` **29 例**：23 正（`packet_count` 4 例 + `min_packets` 19 例），**与实测 pcap 帧数 23/23 逐例一致**（`tshark -r … | wc -l`）；**88 条字段断言逐条机读复核，0 失配**（含 `distinct_values` 集合比较）；6 负 `expect` 键集合**严格 `{expect_error,error_contains}`**，3 例在案 pcap 均 **0 帧**；**非负例 23/23 顶层键仅 `{layers}`（+3 例 `strategy_fc`），零残留**；层形 `[ip,udp,dns]` ×29；层内 `dns` 已带 14 键（与 registry Fields 逐键一致，机读实测）。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **M-1 confirmed 缺陷（最严重）**：`dns_edns0`（#7）的 EDNS0 **未生效**——实测 pcap 与 `dns_smoke_01` 逐字节相同（71B，ARCOUNT=0），而 `summary` 声称 "→附加节ARCOUNT=1"、`notes` 称 "RFC 6891 OPT"。**该例是假绿**（只断言 1 条 `dns.qry.name`）。根因 = 单问路径 `udp_payload_size=0` 早退（设计 §9.2）。
2. **N-4 锚词来源与设计文档不一致**：`dns_neg_rcode` 命中**框架 V9 范围门**（`out of range [0,15]`），而设计 §7 表列的 `dns.go:104` 分支（`exceeds the 4-bit field`）**不可达**（G-DNS-7）。
3. **3 个负例无 pcap 留档**：`dns_neg_flat`/`dns_neg_rcode`/`dns_neg_static_copy`——本车道**已用代码探针复现其拒绝**（`BuildLayersPlanner` 实测命中锚词），但未走完整 MCP 链路留 pcap（G-DNS-8）。
4. **NIC 路径零用例**：29/29 `nic_capture` 计数 = 0（§1 诚实标注）——双输出契约尚未落地。
5. **无 frames hex 断言**：23 正例全部走 `dns.*` 字段通道，**零 `frames` 断言**（与 opcua 相反）。这是**合理选择**（DNS dissector 完备，字段断言更可靠且更强），但须登记——**若未来 tshark 版本字段名变动，全部断言会同时失效**（无 hex 兜底）。
6. **`dns_edns0` 之外的 EDNS0 面零覆盖**：DO 位（`dnssec_ok`）、`udp_payload_size` 非 0、扩展 RCODE、OPT 选项数据——**全部零用例**（A′）。
7. **DS/DNSKEY 只断言 4 条**：#27 断言 `key_id`（未断言 `algorithm`/`digest_type`/digest 内容）；#28 断言 `protocol`（未断言 `key_flags`/`algorithm`/public_key 内容）——**编码变体（hex/base64）的"内容正确性"未直接断言**（A′ 增强面）。
8. **SRV/NAPTR 字段断言不全**：#25 断言 9 条（service/proto/name/port/target 全，**priority/weight 未断言**）；#29 只断言 `order`（**preference/flags/service/replacement 未断言**）——A′ 增强面。
9. **`dns_neg_flat` 的形状是"故意违规"**：`spec_json` = `{layers, dns:{}}`（`layers` 与顶层空 `dns` **并存**）——**这是 presence 负例的标准形状，不是残留**（设计 §12.1 已点名此形状）。收官自查「非负例顶层键 = 0」不受其影响。
10. **结果文档 pcap 链接全死（G-DNS-9）**：tracked 产物 `trafficgen/docs/protocol-pcap-test/dns.md` 的 23/23 正例 `[pcap](dns/<id>.pcap)` 链接**指向不存在的目录**（`docs/protocol-pcap-test/dns/` 0 个 pcap）。**注意本协议不适用 pcep G-PCEP-11 的"末次提交早于判死提交"口径**（`793dfee` 2026-09-19 **晚于** `0417be5` 2026-09-13）——本缺口是"**tracked 产物内容与仓库状态不符**"，不是"过期未复跑"。归属**代码阶段**（P5 重跑后重生成）。

### 8.3 逐条去向表（29 行）

| 存量 id | T-编号 | 去向 | 改写动作（P4） |
|---|---|---|---|
| `dns_smoke_01` | T1 | **保留** | 形状已合规；可补 `dns.flags.opcode=0` 断言 |
| `dns_neg_flat` | T2 | **保留** | 形状已合规（presence 负例标准形）；无 |
| `dns_neg_static_copy` | T3 | **保留** | 无 pcap，P4 补跑留档 |
| `dns_aaaa` | T4 | **保留** | 无 |
| `dns_response` | T5 | **保留** | 可补 `dns.resp.ttl=300` 断言 |
| `dns_nxdomain_soa` | T6 | **改写** | 补 `dns.count.auth_rr=1` + `dns.soa.mname`/`rname` 断言（本轮实测已复核） |
| **`dns_edns0`** | T7 | **改写（M-1）** | ①修早退条件；②补 `dns.count.add_rr=1`；③改 `summary`/`notes` 文案（现状与实测相反）；④重跑后钉帧长 71→82 |
| `dns_name_dynamic` | T8 | **保留** | 无 |
| `dns_qtype_dynamic` | T9 | **保留** | 无 |
| `dns_txid_dynamic` | T10 | **保留** | 无 |
| `dns_neg_tcp` | T11 | **保留** | 可补"链载体 tcp 但 transport 未写"的第二负例（今日 Plan 期 8 包 0 payload，G-DNS-2） |
| `dns_neg_rcode` | T12 | **保留** | 锚词来源登记（V9 门，G-DNS-7）；P4 补 pcap |
| `dns_neg_empty_name` | T13 | **保留** | 无 |
| `dns_multi_question` | T14 | **保留** | 可补 `dns.qry.class=0x0001,0x0001` 断言 |
| `dns_multi_answer` | T15 | **保留** | 可补 `dns.resp.name=example.com,example.com`（无压缩证据） |
| `dns_cname_chain` | T16 | **保留** | 可补 `dns.resp.type=5,1` 顺序断言 |
| `dns_neg_long_domain` | T17 | **保留** | 可补 253 边界正例（A′） |
| `dns_retry_same_txid` | T18 | **保留** | 无 |
| `dns_v6_query` | T19 | **保留** | 可补 `ipv6.src/dst` 断言 |
| `dns_aaaa_response` | T20 | **保留** | 无 |
| `dns_mx_response` | T21 | **保留** | 无 |
| `dns_txt_response` | T22 | **保留** | 无 |
| `dns_ns_response` | T23 | **保留** | 无 |
| `dns_ptr_response` | T24 | **保留** | 无 |
| `dns_srv_response` | T25 | **改写** | 补 `dns.srv.priority=10` / `dns.srv.weight=20` 断言 |
| `dns_v6_aaaa_response` | T26 | **保留** | 可补 `ipv6.src/dst` 断言 |
| `dns_ds_response` | T27 | **改写** | 补 `dns.ds.algorithm=8` / `dns.ds.digest_type=2` 断言 |
| `dns_dnskey_response` | T28 | **改写** | 补 `dns.dnskey.algorithm=8` / `key_flags` 断言 |
| `dns_naptr_response` | T29 | **改写** | 补 `preference=50`/`flags=S`/`service=sip+E2U`/`replacement` 断言 |

**统计（机读复算）**：**保留 23 + 改写 6（含 M-1 的 #7）= 29；作废 0；等价覆盖 0**。**本协议存量非负例 23/23 顶层零残留**（与 opcua/thrift 等协议同为纯层链形，**非全仓唯一**；见设计 §12.1 注）。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

建议在主线程合入后，于 `coverage_gate.py` 的 dns 段登记下列断言（**每条均可从本契约与 cases JSON 直接机读，不需新造事实**）：

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases['dns']) == 29` 且 ID 集合 = §2 二十九项，顺序一致 | 本契约 §2 |
| 2 | 23 正例 `spec_json` 顶层键 ⊆ `{layers}`（**本协议非负例零游离键**）；3 例追加 `strategy_fc` | 本契约 §1；设计 §12.1 |
| 3 | 23 正例 `packet_count`/`min_packets` == `1 + (is_response ? 1 : 0)`（`is_response` 由层内 spec 推出） | 设计 §9 公式 |
| 4 | 6 负例 `expect` 键集合 == `{expect_error, error_contains}`（**今日即成立**） | 本契约 §4 |
| 5 | 负例 `error_contains` ∈ 代码锚词集 `{"no longer accepts a top-level dns sub-config", "static four-tuple", "tcp transport not supported", "out of range [0,15]", "query_name (domain) is required", "exceeds max 63 octets"}` | 设计 §7 |
| 6 | 非负例顶层键计数 == 0（**今日已成立**） | 设计 §12.1 |
| 7 | 每正例至少一条 `dns.*` 字段断言（**23/23 成立**） | 本契约 §3 |
| 8 | 层形恒 `[ip,udp,dns]`（29/29，含 2 个 v6 例地址住 `layers[0].ip`） | 本契约 §1 |
| 9 | **M-1 修复后**：`dns_edns0` 的 `expect.fields` 含 `{"field":"dns.count.add_rr","value":"1"}` | 设计 §9.2 |
| 10 | 多答/多问例的 `dns.*` 断言值为**逗号聚合形**（`dns.a` 含 `,`；`dns.qry.name` 含 `,`） | 本契约 §1 进制纪律 |

**另注意**：`trafficgen/docs/protocol-pcap-test/dns.md` 的 29/29 pass **其 pcap 链接全为死链**（`docs/protocol-pcap-test/dns/` 目录不存在，0 个 pcap；G-DNS-9）——**不得作为"今日已复跑"依据**。**注意本协议不适用 pcep G-PCEP-11 的"末次提交早于判死提交"口径**（`793dfee` 2026-09-19 晚于 `0417be5` 2026-09-13）；本缺口是"tracked 产物内容与仓库状态不符"。

## 10. 修订记录

- v1.0.0（2026-09-29）：P-PIPE 文档轨批次二 #108 as-built。**本协议无旧编号用例文档**，编号体系承 D-DNS-1 补遗 T-DNS-1…29；29 例存量逐条机读审计（§8.1：包数 23/23 一致、**88 条字段断言 0 失配**、非负例顶层零残留、6 负例形状干净）；**M-1 confirmed 缺陷**（§3.5/§8.2 第 1 条：`dns_edns0` 假绿——EDNS0 未生效）；§5 三源回指 + 对账（**逐表重数，不做跨表加总**）；§6 P3 固定动作（**三项全不适用**——无连接协议；A′ 17 例；**B′ 为空**）；§7 执行建议（含进制纪律）；§8 存量审计（**保留 23 + 改写 6 + 作废 0**）；§9 覆盖反查门建议断言行 10 条。自审 3 轮，末轮干净。
