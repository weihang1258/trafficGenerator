# #108 dns（域名系统 · RFC 1035 底座 + EDNS0/多记录类型扩展，UDP 53 主载体 / TCP 53 双载体）设计契约

> 版本：v1.0.0（P-PIPE 文档轨批次二 as-built 定稿；修订记录见 §15）
> 日期：2026-09-29
> 车道：文档轨（批次二，编号 108）
> 前序基线：**本协议无旧编号设计文档**（`docs/protocol-designs/` 无 `NN-dns-*`；历史实现说明见 `docs/design/backend/13-DNS-ICMP-ARP实现.md` v1.0 2026-04-01，是**设计意图稿非契约**，与本版冲突处以本版为准）。内部设计契约现住 `docs/CODE_DESIGN.md` D-DNS-1 条目（顶层 dns 子映射迁入层内 + 层动态放开 name/query_type/txid，2026-09-15 验收）+ 四条补遗（T-DNS-14/15、16..19、20..25、26..29）。
> 配套用例：`docs/protocols/dns/testcase.md` v1.0.0（T-DNS-1…T-DNS-29）
> 规范基线：① **RFC 1035**（DNS 实现与规范：§4.1 报文格式 / §4.1.1 头 / §4.1.2 四段 / §4.1.4 名字压缩 / §2.3.4 名字长度 / §3.1 label 长度 / §3.2.1 RR 格式 / §3.3.13 SOA / §3.3.14 TXT / §3.4.1 A / §6.2.5 负缓存 / §4.2.1 UDP 载体 / §4.2.2 TCP 载体）；② **RFC 6891**（EDNS0 OPT 伪 RR §6.1 + 扩展 RCODE）；③ **RFC 4033/4034**（DNSSEC：DO 位 / DS §5 / DNSKEY §2）；④ **RFC 3596 §2.2**（AAAA）；⑤ **RFC 2782**（SRV）；⑥ **RFC 3401 §4.1**（NAPTR）；⑦ **RFC 7766**（DNS over TCP 现代用法）；⑧ 本机 tshark 3.6.14 `dns.*` 字段表（**327 字段**，实测）+ **29 例实测 pcap**（`/tmp/mcp-pcaps/dns/`，包数/字段值/偏移的唯一权威）；⑨ 本仓库落码（`internal/protocol/dns/` 五文件 + 接线，§11）。
> 白话一句：**互联网的电话簿查询——12 字节固定头（谁在问、要问什么类型、几个问题），后面跟问题段，响应再跟答案段。域名不是整串写的，是按点切成一段段、每段前面加一个长度字节，结尾补一个 0；同一个域名第二次出现时可以用 2 字节指针指回前面（省字节）。所有多字节字段都是大端。**

## 0. 本版沿革与本协议的特殊性（门1 必答：基线继承关系）

本协议**不是续号重做**——`docs/protocol-designs/` 下**从无 dns 设计文档**（机读实测：`ls docs/protocol-designs/ | grep -i dns` 零命中）。因此本版**没有"旧稿校正"章**，取而代之的是**"实现沿革 + 现存契约对照"**：

| # | 来源 | 内容 | 本版处置 |
|---|---|---|---|
| 1 | `docs/design/backend/13-DNS-ICMP-ARP实现.md` v1.0（2026-04-01） | `pkg/protocols/dns.go` 的 `DNSSpec{Domain, QueryType, SrcIP, DstIP, SrcPort, Response, ResponseIP}` + `PlanDNSFlow` | **设计意图稿，非契约**：字段名（`Response` vs 现行 `is_response`）、包结构（`PacketConfig` 直发 vs 现行层链事件）、TxID（`rand.Intn` **随机** vs 现行确定性 0x1234 回退）**三处均与现行实现不符**；本版不承其任何字段名与取值，仅登记为历史层 |
| 2 | `docs/CODE_DESIGN.md` D-DNS-1（2026-09-15，**已验收 P6**） | 顶层 `dns` 子映射迁入层内 14 键；`CheckProtoFlat` dns presence 判死；`layer_dyn.go` allowlist 开 `name`/`query_type`/`txid`；静态复制门业务层逃生口 | **本版承其全部裁定**（§2/§3/§7/§12），逐条给出 as-built 证据行号 |
| 3 | `docs/CODE_DESIGN.md` D-DNS-1 补遗 ×4（2026-09-15/16） | T-DNS-14/15（多问多答）、16..19（CNAME 链/长度门/重传/v6）、20..25（六类 RR 问答）、26..29（v6 问答 + DNSSEC/NAPTR） | **本版承其用例编号体系**（T-DNS-N ≡ 本版 §9 第 N 项），29 例逐条对齐 |
| 4 | `docs/TEST_CASES.md` T-DNS-* | 用例编号登记 | 本版 testcase §2 逐条回指 |

**本协议特殊性（须写清，不得含糊）**：

1. **DNS 是二进制 TLV 报文协议**，不是文本行协议：12B 固定头 + 四段（Question/Answer/Authority/Additional），段内元素为 **TLV 结构**（NAME 变长 + TYPE/CLASS/TTL/RDLENGTH 固定 + RDATA 变长）。逐字段字节偏移与总长度公式见 §3。
2. **name 压缩指针（0xC0）与 label 长度前缀是本协议特有编码**。实现中**指针编码已落码但零使用**（`wireRR.namePtrTo` 字段存在、`appendRR` 有 `0xC000|off` 分支，**无任何调用方置位**——§3.6 诚实声明 + G-DNS-1）。
3. **RFC 1035 是底座，但现网用扩展**：EDNS0（RFC 6891）、多记录类型（A/AAAA/CNAME/NS/PTR/MX/TXT/SOA/SRV/NAPTR/DS/DNSKEY）——§4 数据场景层逐类型列值域与边界。
4. **UDP 53 与 TCP 53 双载体**（TCP 有 2B 长度前缀）。**本版现状：UDP 载体全量可用；TCP 载体在链上被显式拒绝**（§2/§7，G-DNS-2），`dns.go` legacy 路径的 TCP 分支（`prefixTCPLength`）**不在链上可达**。
5. **dns 是被多协议依赖的底座**：`dns` 层 `OptionalOn ["tls"]`（TLS 可作其底座）；反向**零协议**声明依赖 dns 层（机读全仓 127 层生成表 + registry 实测：**无任何层 `DependsOn`/`OptionalOn`/`TransportOn` 含 `dns`**）。dns **不作为其他协议的层底座**——`doh`/`mdns` 各带独立 wire 编码器（不 import `protocol/dns`），`gre` 用例把 `{"dns":{}}` 当**内层载荷**用（§4 地址与流层、G-DNS-3）。

**产物过期登记（重要，G-DNS-9）**：`trafficgen/docs/protocol-pcap-test/dns.md`（**tracked 产物**，`git ls-files` 可证）写 "Cases: 29 — pass 29, fail 0, error 0"。该文件末次提交 `793dfee`（**2026-09-19**），**晚于**判死提交 `0417be5`（2026-09-13）——故本协议**不适用** pcep G-PCEP-11 那条"末次提交早于判死提交"的口径。**但**：`docs/protocol-pcap-test/dns/` 目录**不存在（0 个 pcap 文件，`git ls-files | grep '\.pcap$'` = 0）**，表中 23 个正例的 `[pcap](dns/<id>.pcap)` 链接**全部指向不存在的文件**（23/23 死链）；6 个负例的 `[pcap]()` 为空链接。**故该 29/29 数字未经今日复跑证实、且无 tracked pcap 留档**——读者不得据此判断套件已复跑。**本车道另行机读复核了 29 例在 `/tmp/mcp-pcaps/dns/` 的实测 pcap**（非 tracked，26 个文件在案），结论见 §0.1，**该复核不等于 tracked 产物有效**。

### 0.1 本车道实测复核结论（2026-09-29，供读者判读产物可信度）

| 项 | 实测 | 结论 |
|---|---|---|
| 正例 pcap 帧数 vs `packet_count`/`min_packets` | **23/23 逐例一致**（`tshark -r … \| wc -l`） | 包数契约成立 |
| 正例字段断言 vs 实测 | **88 条断言逐条复核，0 失配**（脚本机读，含 `distinct_values` 集合比较） | 字段断言契约成立 |
| 负例 pcap | 仅 3/6 在案（`dns_neg_empty_name`/`dns_neg_long_domain`/`dns_neg_tcp`，**均 0 帧**） | 3 例未经本车道复跑证实（G-DNS-8） |
| **`dns_edns0`** | **实测 pcap 与 `dns_smoke_01` 逐字节相同（71B，ARCOUNT=0）** —— 该例的 EDNS0 未生效 | **confirmed finding M-1**（§9.2） |

## 1. 范围、profile 与实现状态边界

本版定义 **DNS（RFC 1035 报文格式）承载于 UDP 53** 的流量生成：单/多问题查询、单/多 RR 响应（A/AAAA/CNAME/NS/PTR/MX/TXT/SOA/SRV/NAPTR/DS/DNSKEY 十二类）、权威节（NXDOMAIN 负缓存）、EDNS0 OPT 附加节、TxID 回显与重传、IPv4/IPv6 承载。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `dns_udp_v1`（主，**唯一可用**） | UDP，fixture 53 | 查询（1 包）+ 可选响应（1 包）；全 12 类 RR；EDNS0；多问多答 | 真实解析器/递归服务器语义 |
| `dns_tcp_v1` | TCP，fixture 53，**2B 长度前缀** | **链上显式拒绝**（`dns: tcp transport not supported by the layer chain yet`，`layer_gen.go:114`）；legacy `dns.NewPlanner` 路径的 `prefixTCPLength` 分支存在但不在链上可达 | — |
| `dns_ipv6_v1` | 同上，仅外层 IPv6 | 同上 | 从 IPv4 fixture 推导 IPv6 地址 |

显式边界（"不实现、不声称、不许静默转换"）：① **不实现 name 压缩指针**（`namePtrTo` 字段与 `appendRR` 的 `0xC000|off` 分支已落码但**零调用方**，见 §3.6）；② **不实现 DNS-over-TCP 链上载体**（G-DNS-2）；③ **不实现 DNS-over-TLS**（`OptionalOn ["tls"]` 已声明但 tls 载体路径未接线，G-DNS-3）；④ 不实现 TSIG/SIG(0) 报文签名、AXFR/IXFR 区域传送、动态更新（UPDATE）；⑤ 不实现 EDNS0 选项数据（OPT RDLEN 恒 0）与扩展 RCODE（>15 由 validator 拒）；⑥ 不实现真实 DNSSEC 签名/验签——DS/DNSKEY 只编**结构字段**（digest hex 解码、public_key base64 解码）；⑦ 不声称响应具备真实服务器语义（生成器按模板回灌，`buildDNSResponseGeneral`）。缺失能力均已在 §14 立项。
> **特别声明（G-DNS-6 伏笔）**：EDNS0 的**查询侧**与 legacy 单问路径存在一处"启用即需要显式 payload size"的分支差（§9.2 M-1 / §7），**`edns0_enabled:true` 单问 + `udp_payload_size` 缺席时 OPT 不落线**——这是 confirmed 缺陷，不是设计意图。

**实现状态（2026-09-29 实测）**：`dns` 层已注册（`registry.go:134`，`CategoryTerminal`，`DependsOn ["udp"]`，`TransportOn ["udp","tcp"]`，`OptionalOn ["tls"]`，**Fields 14 键**）；生成器 + 校验器已落码（`internal/protocol/dns/` 六文件 3495 行，含 4 个 `_test.go`）；`allowedProtocols["dns"]=true`（`protocols.go:38`）；层内 translate 已接线（`chain_planner_translate.go:1957`）；缺省目的端口 53（`chain_planner.go:1033`）；`CheckProtoFlat` 有 dns presence 分支（`strategy_convert.go:8650`）；动态 allowlist 有 `dns` 行（`layer_dyn.go:37`）；29 语义用例已落 `cases/dns.json`。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`udp.dstport`、`dns.*` 字段、`ipv6.version`）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）。**现状诚实标注**：存量 29 例 `nic_capture` 计数 = **0**（机读 `grep -c nic_capture cases/dns.json` = 0）——**今日只有 pcap 侧实证**，NIC 路径为设计契约尚未落地（P4 补 `nic_capture` 开关用例后方可声称双输出）。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, udp, dns]`（引擎自动补 `ip`；最小链 `[udp, dns]`）。dns 报文是 UDP payload 的应用层字节流；**一个 MessageEvent = 一个 UDP datagram**（`layer_gen.go:14` 生成器契约）。

**层链载体契约（实测）**：

| 用户写 | 补全链 | 结果 |
|---|---|---|
| `[{"dns":{}}]` | `ip → udp → dns` | 可用（`TransportOn[0]` = udp 为默认） |
| `[{"udp":{}},{"dns":{}}]` | `ip → udp → dns` | 可用 |
| `[{"tcp":{}},{"dns":{}}]` | `ip → tcp → dns` | **补全通过，但 Plan 期拒**（`transport` 值空 ≠ 链载体 tcp；生成器 `layer_gen.go:34-36` 只接受 `Transport==""`/`"udp"`，链载体 tcp 下 DNS 报文被塞进 TCP 全握手流，`layer_gen.go:20-21` 注释明写此语义分叉不可接受）→ **实测 8 包、DNS payload 0 字节**（G-DNS-2） |
| `[{"tcp":{}},{"udp":{}},{"dns":{}}]` | — | `transport layer duplicated` 拒（V3） |
| `[{"udp":{}},{"dns":{"transport":"tcp"}}]` | — | **Validate 同步拒**（`layer_gen.go:113-115`） |

端口：DNS `53`（IANA，UDP/TCP 同名）。缺省由 `chain_planner.go:1033` 的 `case "dns": spec.DstPort = 53` 补齐（`validateSpecBase` 内，先于协议级 validator）；源端口**无协议级缺省**（`chain_planner.go:892-895` 明写 dns 源端口沿用 spec，可为 0 上包；用例惯例显式 12345）。fixture 统一 `dst_port=53`。

固定偏移：无 VLAN/IP options/UDP 无选项，**每帧 DNS 消息起点 = IPv4 offset 42**（14+20+8）、**IPv6 offset 62**（14+40+8）。DNS 消息内字段偏移按 §3.1 头布局递推；**变长字段之后的偏移不稳**（§3.3 注）。

> **口径警示（本协议高频误记点）**：`42`/`62` 是 **DNS 消息起点**（UDP payload 起点）；`54`/`74` 是 **TCP payload 起点**（TCP 有 20B 头）——本协议主载体是 UDP，**用 54/74 是错的**。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；**本协议存量 23 正例已是此形**）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"udp": {"src_port": 12345, "dst_port": 53}},
    {"dns": {"name": "example.com", "query_type": 1}}
  ]
}
```

多流样例（数量只走 `flow_control`；动态值住层内，四元组可留空走 worker 保底递增 §12）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"udp": {"src_port": 12345, "dst_port": 53}},
    {"dns": {"name": {"strategy": "list", "list": ["a.com", "b.com"]}, "query_type": 1}}
  ],
  "strategy_fc": {"type": "flows", "value": 2}
}
```

> 存量动态用例用**顶层 `strategy_fc`**（`{"type":"flows","value":2}`）而非 `flow_control`——两键均在顶层白名单内，本版按存量如实登记（§12.1）。

## 3. 线格式编码（逐字段，按代码钉）

### 3.1 Header（12 字节，RFC 1035 §4.1.1）

| 偏移 | 字段 | 类型/尺寸 | 端序 | 本实现取值 |
|---|---|---|---|---|
| 0–1 | ID | uint16 | **大端** | `cfg.TxID`；**0 → 0x1234**（`buildDNSQuery:379-381`、`buildDNSMessage` 调用侧同款回退） |
| 2–3 | Flags | uint16 | 大端 | **查询恒 `0x0100`**（QR=0, Opcode=0, RD=1；`buildDNSQuery:388`、`buildDNSMessage` 调用侧 `layer_gen.go:65`）；**响应 = `0x8180 \| (rcode & 0x0F)`**（QR=1, RD=1, RA=1；`buildDNSResponseGeneral:817`；legacy `buildDNSResponse:430` 恒 `0x8180`） |
| 4–5 | QDCOUNT | uint16 | 大端 | `len(questions)`（`buildDNSMessage:704`）；legacy 单问路径恒 1 |
| 6–7 | ANCOUNT | uint16 | 大端 | `len(answers)`；legacy 单 RR 路径恒 1 |
| 8–9 | NSCOUNT | uint16 | 大端 | `len(authority)` |
| 10–11 | ARCOUNT | uint16 | 大端 | `len(additional)`；**查询侧 EDNS0 走 `buildDNSQueryWithEDNS0:634-635` 硬写 `00 01`**，非 EDNS0 时 0 |

**总长度公式**：`12 + Σ question + Σ answer + Σ authority + Σ additional`，其中每 question = `QNAME + 4`，每 RR = `NAME + 10 + RDLENGTH`。

### 3.2 名字编码（RFC 1035 §3.1/§2.3.4/§4.1.4）——本协议特有

**逐 label 长度前缀 + 0x00 终止**（`encodeDomainName:558-569`）：

```
domain = "example.com"
splitLabels → ["example", "com"]              # splitLabels:572-594
wire   = 07 'example' 03 'com' 00             # 13 字节
```

| 规则 | 实现 | 依据 |
|---|---|---|
| 每 label：1 字节长度 + label 字节 | `result = append(result, byte(len(label)))`（`:562-563`） | RFC 1035 §3.1 |
| 结尾 0x00（root label） | `result = append(result, 0)`（`:566`） | 同上 |
| 连续点产生**空 label**（`a..b` → `01 'a' 00 01 'b'`） | `splitLabels:581` 遇 `.` **无条件** append（含空段） | RFC 1035 §3.1（显式注释） |
| **尾点（FQDN）不产生额外空 label** | `splitLabels:589` `if start < len(domain)` 守卫 | 同上（root 由 0x00 终止符代表） |
| **单 label ≤ 63 字节** | **validator 拒**（`validateDNSConfig:116-120`，锚词 `exceeds max 63 octets`） | RFC 1035 §3.1 |
| **全名 ≤ 253 字符** | **validator 拒**（`:113-115`，锚词 `exceeds max 253 characters`） | RFC 1035 §2.3.4 |
| **长度字节截断（超 255 静默回绕）** | **未在编码器守卫**——靠上两条 validator 前置拦截（`byte(len)` 在 `:562` 无守卫） | 实现缺口，见 G-DNS-4 |

**长度门检查面（`dnsQueryNames:535-555`）**：`Domain` + `Questions[].Name` + `Answers[]/Authority[]` 的 **`Name`/`Target`/`MName`/`RName` 四字段**逐个入检。**`NAPTR` 的 `Flags`/`Service`/`Regexp` 与 `TXT` 的 `Text` 不经此门**（它们是 character-string，走各自的 255 截断，§3.5）。

**name 压缩指针（RFC 1035 §4.1.4）——已落码、零使用（G-DNS-1）**：

| 项 | 事实 |
|---|---|
| 结构 | `wireRR.namePtrTo uint16`（`dns.go:668`） |
| 编码分支 | `appendRR:730-733`：`if rr.namePtrTo != 0 { PutUint16(ptr, 0xC000\|rr.namePtrTo) }` |
| 调用方 | **零**（机读 `grep -rn 'namePtrTo' --include=*.go .` = 4 命中，全在 `dns.go` 的定义/注释/读取侧；**无任何 `wireRR{... namePtrTo: …}` 构造**） |
| 结论 | **本实现永不发压缩指针**——所有 NAME 恒为完整展开编码。响应中 Question 与 Answer 的同一域名**各写一遍**（如 `dns_smoke_01` 类响应 = 13B question name + 13B answer name） |

### 3.3 Question 段（RFC 1035 §4.1.2）

每项 = `QNAME`（§3.2 变长）+ `QTYPE`（uint16 大端）+ `QCLASS`（uint16 大端）。

- **QCLASS 缺省 IN=1**（`wireQuestion.qclass` 0 → 1，`layer_gen.go:56-58`；`buildDNSMessage` 不默认，默认在调用侧）。
- **多问路径**（`len(Questions)>0`）走 `buildDNSMessage`（`layer_gen.go:48-65`）；**单问路径**走 legacy `buildDNSQuery`（`:67`）。两路径**头 Flags 同为 0x0100、QDCOUNT 同为 1**，差异只在 EDNS0 分支（§9.2 M-1）。
- **偏移注**：第一个 question 的 QTYPE 偏移 = `42 + len(QNAME)`（UDP/IPv4）；变长之后不可硬编码。

### 3.4 Answer / Authority 段（RR 格式，RFC 1035 §3.2.1）

`appendRR:729-747` 逐 RR 写：

| 段 | 尺寸 | 说明 |
|---|---|---|
| NAME | 变长（或 2B 指针，本实现恒展开） | `rr.name`；**空名 → 单字节 `0x00`**（`rrToWire:836-838`） |
| TYPE | 2B 大端 | `rr.rtype` |
| CLASS | 2B 大端 | **缺省 IN=1**（`rrToWire:831-834`） |
| TTL | 4B 大端 | `rr.TTL` → 0 时取 `cfg.TTL` → 仍 0 则 **300**（`rrToWire:824-830`） |
| RDLENGTH | 2B 大端 | `len(rr.rdata)`（`:743`） |
| RDATA | 变长 | 按 TYPE 分派，§3.5 |

**legacy 单 RR 路径**（`buildDNSResponse:423-530`）：恒 1 question + 1 answer，TTL **硬写 300**（`:447`），CLASS 恒 IN（`:446`），RDLENGTH 按 §3.5 分派后回填（`:518`）。

### 3.5 RDATA 逐类型规格（`encodeRDATA:851-980`）

| TYPE | 名 | RDATA 布局 | 尺寸公式 | 缺省/回退（`rr` 字段为空时） |
|---:|---|---|---|---|
| 1 | A | IPv4 4B | **恒 4** | `rr.IP` 解析失败或非 v4 → **127.0.0.1**（`:860`） |
| 2 | NS | 域名 | `len(encodeDomainName(target))` | `Target` 空 → `target.example.com`（`:871-872`） |
| 5 | CNAME | 域名 | 同上 | 同上 |
| 6 | SOA | MNAME + RNAME + 5×uint32 | `len(mname)+len(rname)+20` | `MName` 空 → `ns1.example.com`；`RName` 空 → `admin.example.com`（`:897-903`）；5 个 uint32 **无默认**（`Serial`/`Refresh`/`Retry`/`Expire`/`Minimum` 原值，全 0 合法） |
| 12 | PTR | 域名 | `len(encodeDomainName(target))` | `target.example.com` |
| 15 | MX | Preference(2B) + 域名 | `2 + len(exchange)` | `Target` 空 → `mail.example.com`；`Preference` **无默认**（0 合法） |
| 16 | TXT | 1B 长度 + 文本 | `1 + min(len(Text),255)` | **>255 截断**（`:888-890`）；空串 → 单字节 `0x00`（合法，RFC 1035 §3.3.14） |
| 28 | AAAA | IPv6 16B | **恒 16** | `rr.IP` 非 v6（含 v4/解析失败）→ **::1**（`:865-868`） |
| 33 | SRV | Priority(2B)+Weight(2B)+Port(2B)+域名 | `6 + len(target)` | `Target` 空 → `target.example.com`；Priority/Weight/Port 无默认 |
| 35 | NAPTR | Order(2B)+Preference(2B)+Flags(cs)+Service(cs)+Regexp(cs)+Replacement(域名) | `4 + (1+len(flags)) + (1+len(service)) + (1+len(regexp)) + len(repl)` | 三个 character-string **各截断 255**（`appendCharString:984-992`）；`Target` 空 → `"."`（`：942-944`，**注意是单点 root，不是 example.com**） |
| 43 | DS | KeyTag(2B)+Algorithm(1B)+DigestType(1B)+Digest | `4 + len(hex_digest)` | `Digest` **hex 解码失败 → 空**（`:953-956`，静默吞错） |
| 48 | DNSKEY | Flags(2B)+Protocol(1B)+Algorithm(1B)+PublicKey | `4 + len(base64_pub)` | `PublicKey` **base64 解码失败 → 空**（`:967-970`，静默吞错） |
| 41 | OPT | 见 §3.7 | 恒 **0**（RDLEN=0） | — |
| 其它 | — | **空 RDATA**（RDLEN=0） | 0 | `default: return nil`（`:975-978`）——RR 结构合法但无内容 |

**静默吞错声明（G-DNS-5）**：DS `Digest` 与 DNSKEY `PublicKey` 解码失败**不报错、不告警**，直接产出空 RDATA（RDLENGTH=0）。用例 `dns_ds_response`/`dns_dnskey_response` 的输入均为合法编码，故未暴露。

### 3.6 名字压缩（RFC 1035 §4.1.4）

见 §3.2 末表：**编码分支存在、零使用**。因此本实现产出的报文**可被任何解析器正确读取**（展开形永远合法），但**体积大于真实 DNS**（响应中重复域名不压缩）。用例断言不受影响（`dns.resp.name` 等字段由 tshark 从展开形正常解出，88 条断言实测全过）。

### 3.7 EDNS0 OPT 伪 RR（RFC 6891 §6.1）

**两套独立实现**（这是 M-1 的根因）：

| 路径 | 函数 | 布局 | 触发条件 |
|---|---|---|---|
| **单问路径** | `buildDNSQueryWithEDNS0:601-641` | 手工 11B：`NAME=0x00`(1) + `TYPE=41`(2) + `CLASS=payload_size`(2) + `TTL=[extRCODE,ver,DO\|Zhi,Zlo]`(4) + `RDLEN=0`(2) | `buildDNSQuery(...,edns0Enabled=true,...)` **且 `udpPayloadSize != 0`**（`:606-608` **早退返回非 EDNS0 基报文**） |
| **多问路径 / 响应路径** | `optWireRR:678-693` → `appendRR` | 同布局，经通用 RR 写出 | 多问：`layer_gen.go:62-64`（**无 size 条件**，size=0 → `optWireRR` 内回退 **4096**）；响应：`buildDNSResponseGeneral:812-814`（同款无 size 条件） |

| 字段 | 值 |
|---|---|
| NAME | `0x00`（root） |
| TYPE | `41`（OPT） |
| CLASS | UDP payload size；**0 → 4096**（`optWireRR:679-681`） |
| TTL 4B | byte0 = extRCODE（**恒 0**）、byte1 = version（**恒 0**）、byte2 = DO\|Z_hi（`dnssec_ok` → **0x80**）、byte3 = Z_lo（恒 0） |
| RDLEN | **恒 0**（无 option 数据） |

**M-1 confirmed 缺陷（§9.2）**：单问路径的 `udpPayloadSize != 0` 早退使 **`edns0_enabled:true` + `udp_payload_size` 缺席（层 schema 默认 0）→ OPT 不落线**，ARCOUNT=0，报文与未启用 EDNS0 逐字节相同。多问路径与响应路径**无此分支**（size=0 回退 4096），故同一配置在两条路径上行为不一致。用例 `dns_edns0` 正是单问 + 缺席 size → **实测 pcap 与 `dns_smoke_01` 完全相同**。

### 3.8 TCP 载体的 2B 长度前缀（RFC 1035 §4.2.2 / RFC 7766 §7）

`prefixTCPLength:646-651`：`out = BE16(len(msg)) || msg`，**长度覆盖其后的 DNS 消息、不含 2B 前缀自身**。**该函数只在 legacy `Plan` 的 `transport=="tcp"` 分支被调用（`dns.go:279/331`）**；链上 `transport:"tcp"` 在 Validate 期即拒（`layer_gen.go:113-115`），**故该前缀今日不落任何用例的线**（G-DNS-2）。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明"问什么（name/type/多问）+ 答什么（answers/authority/rcode/EDNS0）"，引擎按固定剧本产出事件（查询 up，可选响应 down），udp 层每事件发一个 datagram；无握手、无挥手、无连接状态。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 递归解析器 A 记录查询 | 单问单答（txid 回显） | #1（`dns_smoke_01`）、#5（`dns_response`） |
| ② AAAA（IPv6 地址）查询 | 同上，QTYPE=28 | #4（`dns_aaaa`）、#20（`dns_aaaa_response`） |
| ③ 别名链（CDN 常见） | CNAME + A 双 RR 响应 | #16（`dns_cname_chain`） |
| ④ 多 A 记录（负载均衡） | 同名单多 RR 响应 | #15（`dns_multi_answer`） |
| ⑤ 邮件路由 | MX 查询（preference + exchange） | #21（`dns_mx_response`） |
| ⑥ 反垃圾/校验（SPF/DKIM） | TXT 查询 | #22（`dns_txt_response`） |
| ⑦ 区域委派 | NS 查询 | #23（`dns_ns_response`） |
| ⑧ 反向解析（PTR，日志/审计） | `in-addr.arpa` PTR 查询 | #24（`dns_ptr_response`） |
| ⑨ 服务发现（SIP/LDAP 类） | SRV 查询（priority/weight/port/target） | #25（`dns_srv_response`） |
| ⑩ DNSSEC 验证链 | DS / DNSKEY 查询 | #27（`dns_ds_response`）、#28（`dns_dnskey_response`） |
| ⑪ 号码/URI 映射 | NAPTR 查询 | #29（`dns_naptr_response`） |
| ⑫ NXDOMAIN 负缓存 | 响应带 authority SOA | #6（`dns_nxdomain_soa`） |
| ⑬ 大响应协商（EDNS0） | 查询带 OPT，声明可收 4096 | #7（`dns_edns0`，**M-1 未生效**） |
| ⑭ 丢包重传（同 TxID 重发） | 固定 txid，双包同 ID | #18（`dns_retry_same_txid`） |
| ⑮ 多问单包（诊断工具） | QDCOUNT=2 | #14（`dns_multi_question`） |
| ⑯ 批量扫描（多域名/多类型） | flows=N + 层动态 | #8/#9/#10（`dns_name_dynamic`/`qtype`/`txid`） |
| ⑰ IPv6 承载（v6 网络解析器） | 同 ①，外层 v6 | #19（`dns_v6_query`）、#26（`dns_v6_aaaa_response`） |

**五层覆盖逐层结论**：

- **功能层**：查询（单/多问）、响应（单/多 RR/权威节/rcode）、EDNS0、重传同 ID——正例 23 条；错误处理 6 类负例（§7）。
- **性能层**：**帧长上界** = 单 UDP datagram（**无 MSS 分段**——UDP 无分段概念，超 MTU 由 IP 层分片，本层不设断言）；实测**最小帧 65B 以太**（`dns_name_dynamic` 的 `a.com` 查询，DNS 23B）、**最大帧 159B 以太**（`dns_naptr_response` 响应，DNS 117B）；**字段长度上界** = 域名 253 / label 63 / TXT 255 / character-string 255（全有 validator 或截断守卫）；**多流并发** = `flows=N` + 层动态（#8/#9/#10）。
- **数据场景层**：**12 类 RR 的值域与边界**——A/AAAA 族匹配（validator 拒不匹配）、域名类（NS/CNAME/PTR/SRV/NAPTR Target）、数值类（MX preference / SRV priority·weight·port / SOA 五 uint32 / DS KeyTag·Algorithm·DigestType / DNSKEY Flags·Protocol·Algorithm）、文本类（TXT 255 截断 / NAPTR 三 character-string）、编码类（DS digest **hex**、DNSKEY public_key **base64**）；**空名/空 RDATA/未知 TYPE**（§3.5 default 分支）今日无例 → A′（§14）。
- **地址与流层**：**IPv4 与 IPv6 双覆盖**（#19/#26 为 v6 承载，实测 offset 62；其余 v4 offset 42）；**单流基线**全正例；**流关联（控制流派生数据流）显式不适用**——DNS 是**单次无状态请求/响应**，无副连接、无会话；**多流（会话内并发流）显式不适用**——单 datagram 单消息，多流由策略级 `flows` 承载；**多会话显式不适用**（无连接概念）。
- **业务层**：十七个现网场景全部有落点（§4 表）。

**次要合法行为边界（当前不实现，均已在 §14 立项；不设正例，亦不得进负例）**：① name 压缩指针（未实现，G-DNS-1）；② DNS-over-TCP 链上载体（显式拒绝，G-DNS-2）；③ DNS-over-TLS（未接线，G-DNS-3）；④ TSIG/SIG(0) 签名、AXFR/IXFR、UPDATE（§1 边界④）；⑤ EDNS0 选项数据与扩展 RCODE（§1 边界⑤）；⑥ 真实 DNSSEC 密码学（§1 边界⑥）；⑦ RST 异常中断（框架 udp 层无此概念；**本层零断言**）。

## 5. 消息/事务模型与状态机

**事务定义**：一次查询 + 可选一次响应（`is_response` 开关）。**多事务** = 多流（`flows=N`）各自一对，流间无关联标识（**TxID 是唯一事务标识**，RFC 1035 §4.1.1；响应 MUST 回显，实现 `buildDNSResponseGeneral:761-764` 与 legacy `buildDNSResponse:424-426` 均读同一 `cfg.TxID`）。

**dns 层无自有状态机**：无握手、无挥手、无连接状态、无保活、无重连。生成器是"按配置产出 1 或 2 个事件"的纯函数。

| 阶段 | 产出 | 用例 |
|---|---|---|
| 查询 | 1 事件（`Up:true`，`layer_gen.go:69`） | 全 23 正例 |
| 响应（可选） | `is_response:true` → 1 事件（`Up:false`，`:88`） | #5/#6/#15/#16/#18/#20–#29 |
| 传输 | udp 层每事件一个 datagram | 全部 |

**事件序（`layer_gen.go:29-89`）**：`transport` 门（`:34-36`）→ 构建查询（多问 `buildDNSMessage` / 单问 `buildDNSQuery`）→ `EmitMsg(Up:true)` → **`if !IsResponse: return`**（`:75-77`）→ 构建响应（`buildDNSResponseGeneral` 若 `Answers>0 || Authority>0 || RCode!=0 || Questions>0`，否则 legacy `buildDNSResponse`，`:83-87`）→ `EmitMsg(Up:false)`。

**自动派生规则**：① 响应**不自动派生**——`is_response` 必须显式 true（与 thrift 的"自动补 REPLY"不同）；② `TxID` 缺省 0 → **0x1234**（两处独立回退：`buildDNSQuery:379-381`、`buildDNSResponseGeneral:761-764`；legacy 响应同）；③ `QCLASS`/`CLASS` 缺省 **IN=1**；④ `TTL` 三级回退 `rr.TTL → cfg.TTL → 300`；⑤ **响应侧 Flags 由 builder 重算**（`0x8180 | rcode`），**不继承查询 Flags**（`buildDNSResponseGeneral:817` 注释明写"this builder does not recompute them"指 `buildDNSMessage`；响应 Flags 在 `buildDNSResponseGeneral` 内一次算定）。

**响应问题段回显规则（RFC 1035 §4.1 MUST）**：`buildDNSResponseGeneral:767-779`——`len(Questions)>0` 则原样回显全部问题；否则用 `Domain`/`QueryType` 合成单问。**这是"响应必须回显问题"的实现点**。

**多流展开（`flows=N`）**：N 条独立流，各自完整查询（+可选响应）；第二流包号起点 = 前一流包数 + 1。**流间状态不串用**（生成器无跨流状态）。动态字段按 `FlowIndex` 确定性取值（§12）。

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流 1 包（查询）或 2 包（查询+响应）；**帧长上界**由字段长度门间接约束（域名 ≤253 → QNAME ≤255B；TXT ≤255B；character-string ≤255B）；**无 MSS 分段**（UDP 载体，超 MTU 由 IP 层分片，本层不声明）；无锁、无 sleep、无跨流共享状态。吞吐数字待 P4 基准，**本版不写承诺**（§6.5）。
- **依据**：事件按配置规模线性产出（1 或 2 个事件，`layer_gen.go` 无循环聚合）；每帧内存 = 该帧 DNS 消息长度（实测 23–117B）+ 各层头；`dnsQueryNames` 会为长度门**分配一个最多 `1+len(Questions)+4×len(Answers)+4×len(Authority)` 的字符串切片**（`dns.go:536`）——**这是本协议唯一的配置规模线性分配**，规模由用户配置决定（非按包）。
- **验收两路（§6.3 强制）**：pcap（`/tmp/mcp-pcaps/dns/`，`<id>.pcap` / 负例 `<id>.neg.pcap`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `dns.*` 字段值、`udp.dstport`、`ipv6.version` 与 `packet_count`，不只断言"任务没报错"。**现状**：NIC 路径**零用例**（§1 诚实标注），P4 补。
- **六类场景落点（§6.6）**：基线（#1，1 帧）/ 目标规模（#15 多答 2 帧、#16 CNAME 链 2 帧）/ 压力上限（#29 NAPTR 响应 **159B 以太帧**为全协议最大；#14 多问 QDCOUNT=2）/ 长时间运行（**不适用**——DNS 无会话，长时间由 `flows=N` 多次展开承载）/ 并发交错（**不适用**——无并发路径）/ 背压（`packet_count` 精确计数守卫帧数漂移；`flows` 总量截断由框架承载）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须由 planner/validator 拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩 UDP 外壳的假成功（实测 3 例在案 pcap 均 **0 帧**）：

| # | 负例 ID | 故障输入 | 代码锚词 | 代码行 | 拒绝层 |
|---:|---|---|---|---|---|
| N-1 | `dns_neg_flat` | 顶层 `dns` 子映射 presence（**空 map 也死**） | `no longer accepts a top-level dns sub-config` | `strategy_convert.go:8650-8654` | CheckProtoFlat（schema 400） |
| N-2 | `dns_neg_static_copy` | `flows=2` + 全静态四元组 | `static four-tuple` | `complete.go` 静态复制门 | ValidateLayers |
| N-3 | `dns_neg_tcp` | 层内 `transport:"tcp"` | `tcp transport not supported` | `layer_gen.go:114` | 层校验器（`RegisterLayerValidator`） |
| N-4 | `dns_neg_rcode` | `response_code:16`（4 位上限 15） | `out of range [0,15]` | `complete.go:325`（V9 范围门，schema `Max:15`） | ValidateLayers |
| N-5 | `dns_neg_empty_name` | `name:""` 且无 `questions` | `query_name (domain) is required` | `dns.go:132-134` | 层校验器 |
| N-6 | `dns_neg_long_domain` | 单 label 64 字节（>63） | `exceeds max 63 octets` | `dns.go:116-120` | 层校验器 |

**负例原子性**：每例单一故障注入；单次执行不得混注（6/6 存量均单注入，机读实测）。

**锚词口径**：`error_contains` 是**子串**判定。**注意 N-4 与 N-5 的锚词来源不同**：N-4 命中**框架 V9 范围门**（`out of range [0,15]`），**不是** `dns.go` 的 rcode 分支（`dns rcode %d exceeds the 4-bit field`，`dns.go:103-105`）——**两者语义重复但字面不同**（G-DNS-7）。N-5/N-6 命中 `dns.go` 的层校验器。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：

| 分支 | 锚词 | 代码行 | 今日可达性（实测） |
|---|---|---|---|
| transport 非法值 | `dns transport %q not supported (allowed: udp, tcp)` | `dns.go:98` | **可达**（实测 `transport:"sctp"` → 命中） |
| rcode > 15（planner 侧） | `dns rcode %d exceeds the 4-bit field (max 15)` | `dns.go:104` | **不可达**（V9 范围门先拒，见 N-4） |
| Questions[i] 空名 | `dns questions[%d]: name is required` | `dns.go:129` | **可达**（实测命中） |
| A/AAAA RR 族不匹配（answers） | `dns answers[%d]: TypeA requires an IPv4 ip` 等 | `dns.go:188-192` | **可达**（实测命中） |
| A/AAAA RR 族不匹配（authority） | `dns authority[%d]: …` | 同上 | **可达**（未实测，同代码路径） |
| ResponseIP 非法 IP | `dns response_ip %q is not a valid IP address` | `dns.go:159` | 可达（legacy 单 RR 路径） |
| ResponseIP 族不匹配（TypeA/AAAA） | `dns TypeA (A record) requires an IPv4 response_ip` | `dns.go:162/165` | **可达**（实测命中） |
| 全名 > 253 | `exceeds max 253 characters` | `dns.go:114` | **可达**（实测 254 拒 / 253 放） |
| DNSConfig 为 nil | `DNS config is required` | `dns.go:90` | 链路径不可达（translate 恒建非 nil，`chain_planner_translate.go:1976-1979`）；legacy 路径可达 |

**不得误报的合法协议事件**：多问单包（#14）；多答单包（#15/#16）；NXDOMAIN + authority SOA（#6）；EDNS0（多问路径，§9.2）；NAPTR 空 Target（合法，编码为 root `.`）；TXT 空文本（合法，单字节 0x00）；未知 TYPE（合法，RDLEN=0）；`response_code:0`（合法默认）；`is_response:false`（合法，单包）。

## 8. 边界

- **帧长**：实测最小以太帧 **65B**（`dns_name_dynamic`，DNS 23B = 12 头 + 7+1+3+1 + 4 问题；**注意 `a.com` 编码为 `01 'a' 03 'com' 00` = 7B**）；最大 **159B**（`dns_naptr_response`，DNS 117B）。IPv6 承载同 DNS 长度，以太帧 +20B（如 `dns_v6_query` 91B vs `dns_aaaa` 71B，DNS 同 29B）。
- **字段上界**：域名全名 **253**（254 拒，实测）；单 label **63**（64 拒，实测）；TXT/character-string **255**（静默截断，非拒绝）；DNS 消息总长**无显式门**（UDP 载体超 MTU 由 IP 分片；TCP 载体的 2B 前缀上限 65535 不可达，因载体被拒）。
- **问题数/答案数**：无上限（`uint16` 计数）；**多问一帧多问题**（非多帧）；**多答一帧多 RR**（非多帧）。
- **QTYPE**：schema `Max:65535`，**无枚举白名单**——任意 uint16 合法；RDATA 按 §3.5 分派，**未列类型 → RDLEN=0**（合法但无内容）。
- **TxID**：`uint16`；**0 = 0x1234**（不可表达"真的用 0"——G-DNS-10）。
- **TTL**：`uint32`；三级回退 `rr.TTL → cfg.TTL → 300`；**显式 0 无法表达**（0 即走回退——G-DNS-10）。
- **RCode**：`uint8`，**0–15**（V9 门 + schema `Max:15`）；**扩展 RCODE 不实现**。
- **端口**：显式 53 全正例；缺省 53（`chain_planner.go:1033`）**今日无例** → A′ 补例。
- **地址族**：v4/v6 独立用例（#19/#26 为 v6）；**异族混写**由框架 `validateSpecBase` 拒（`SrcIP … DstIP … must be same IP version`），**今日无例** → A′。
- **载体**：UDP 可用；**TCP 链上拒**（§2/§7 N-3）。
- 不得产生回绕长度或超量分配（长度门在 validator 前置）。

## 9. 原子 ID 与完成定义（29 个唯一语义 ID，顺序为权威）

| # | ID | 类型 | 覆盖 | 包数（实测） |
|---:|---|---|---|---:|
| 1 | `dns_smoke_01` | 正 | §3.1/§3.3：单问基线（A，txid 默认 0x1234，QR=0 RD=1） | 1 |
| 2 | `dns_neg_flat` | 负 | §7 N-1 顶层 dns presence 判死 | —（无 pcap） |
| 3 | `dns_neg_static_copy` | 负 | §7 N-2 静态复制拒 | —（无 pcap） |
| 4 | `dns_aaaa` | 正 | §3.3：QTYPE=28（RFC 3596） | 1 |
| 5 | `dns_response` | 正 | §3.1/§3.4：响应包（txid 回显 + A RDATA） | 2 |
| 6 | `dns_nxdomain_soa` | 正 | §3.4/§3.5：rcode=3 + authority SOA（RFC 1035 §6.2.5） | 2 |
| 7 | `dns_edns0` | 正 | §3.7：EDNS0 OPT（**M-1 未生效**） | 1 |
| 8 | `dns_name_dynamic` | 正 | §12：`name` list 动态（flows=2，双域名 distinct） | 2 |
| 9 | `dns_qtype_dynamic` | 正 | §12：`query_type` inc 动态（1→28） | 2 |
| 10 | `dns_txid_dynamic` | 正 | §12：`txid` inc 动态（1000→1001） | 2 |
| 11 | `dns_neg_tcp` | 负 | §7 N-3 transport=tcp 链上拒 | —（0 帧） |
| 12 | `dns_neg_rcode` | 负 | §7 N-4 rcode=16 越界 | —（无 pcap） |
| 13 | `dns_neg_empty_name` | 负 | §7 N-5 空域名 | —（0 帧） |
| 14 | `dns_multi_question` | 正 | §3.3：QDCOUNT=2（RFC 1035 §4.1.2） | 1 |
| 15 | `dns_multi_answer` | 正 | §3.4：ANCOUNT=2（多 A） | 2 |
| 16 | `dns_cname_chain` | 正 | §3.5：CNAME + A 别名链 | 2 |
| 17 | `dns_neg_long_domain` | 负 | §7 N-6 单 label 64B 超限 | —（0 帧） |
| 18 | `dns_retry_same_txid` | 正 | §5：固定 txid 1001 双包同 ID（重传语义） | 2 |
| 19 | `dns_v6_query` | 正 | §2/§4：IPv6 承载查询（offset 62） | 1 |
| 20 | `dns_aaaa_response` | 正 | §3.5：AAAA 问答配对（RFC 3596 §2.2） | 2 |
| 21 | `dns_mx_response` | 正 | §3.5：MX（preference + exchange，RFC 1035 §3.3.9） | 2 |
| 22 | `dns_txt_response` | 正 | §3.5：TXT（RFC 1035 §3.3.14） | 2 |
| 23 | `dns_ns_response` | 正 | §3.5：NS（委派链） | 2 |
| 24 | `dns_ptr_response` | 正 | §3.5：PTR（`in-addr.arpa` 反向） | 2 |
| 25 | `dns_srv_response` | 正 | §3.5：SRV（priority/weight/port/target，RFC 2782） | 2 |
| 26 | `dns_v6_aaaa_response` | 正 | §2/§3.5：v6 承载 AAAA 问答 | 2 |
| 27 | `dns_ds_response` | 正 | §3.5：DS（RFC 4034 §5，digest hex） | 2 |
| 28 | `dns_dnskey_response` | 正 | §3.5：DNSKEY（RFC 4034 §2，public_key base64） | 2 |
| 29 | `dns_naptr_response` | 正 | §3.5：NAPTR（RFC 3401 §4.1） | 2 |

**包数公式**：单流 = `1 + (is_response ? 1 : 0)`。校验（机读复算）：**查询型 8 例**（#1/#4/#7/#8/#9/#10/#14/#19，各 1 包，含 `flows=2` 的 3 例各发 2 流 × 1 包 = 2）；**响应型 15 例**（各 2 包）。8 + 15 = 23 ✓ **23/23 与实测 pcap 逐例一致**（§0.1）。负例无 `packet_count`（3 例在案 pcap 实测 0 帧）。

**T-编号对照（承 D-DNS-1 补遗体系）**：`dns_smoke_01` ≡ T-DNS-1；`dns_neg_flat` ≡ T-DNS-2；`dns_neg_static_copy` ≡ T-DNS-3；`dns_aaaa` ≡ T-DNS-4；`dns_response` ≡ T-DNS-5；`dns_nxdomain_soa` ≡ T-DNS-6；`dns_edns0` ≡ T-DNS-7；`dns_name_dynamic` ≡ T-DNS-8；`dns_qtype_dynamic` ≡ T-DNS-9；`dns_txid_dynamic` ≡ T-DNS-10；`dns_neg_tcp` ≡ T-DNS-11；`dns_neg_rcode` ≡ T-DNS-12；`dns_neg_empty_name` ≡ T-DNS-13；`dns_multi_question` ≡ T-DNS-14；`dns_multi_answer` ≡ T-DNS-15；`dns_cname_chain` ≡ T-DNS-16；`dns_neg_long_domain` ≡ T-DNS-17；`dns_retry_same_txid` ≡ T-DNS-18；`dns_v6_query` ≡ T-DNS-19；`dns_aaaa_response` ≡ T-DNS-20；`dns_mx_response` ≡ T-DNS-21；`dns_txt_response` ≡ T-DNS-22；`dns_ns_response` ≡ T-DNS-23；`dns_ptr_response` ≡ T-DNS-24；`dns_srv_response` ≡ T-DNS-25；`dns_v6_aaaa_response` ≡ T-DNS-26；`dns_ds_response` ≡ T-DNS-27；`dns_dnskey_response` ≡ T-DNS-28；`dns_naptr_response` ≡ T-DNS-29。**序号以 cases JSON 顺序为权威**（JSON 中 `dns_neg_flat`/`dns_neg_static_copy` 在第 2/3 位，与 T 编号 1..13 的文档序不同）。

### 9.1 RCODE 取值（RFC 1035 §4.1.1）

| 名称 | 值 | 本实现 |
|---|---:|---|
| NOERROR | 0 | 缺省（`buildDNSResponseGeneral` flags 低 4 位 0） |
| FORMERR | 1 | 可配（`response_code`） |
| SERVFAIL | 2 | 可配 |
| NXDOMAIN | 3 | **#6 用例**（`dns.flags.rcode=3` 实测） |
| NOTIMP | 4 | 可配 |
| REFUSED | 5 | 可配 |
| 6–15 | — | 可配（无标准名） |
| >15 | — | **拒**（N-4） |

### 9.2 M-1：EDNS0 单问路径 `udp_payload_size=0` 早退（confirmed finding）

| 项 | 值 | 出处 |
|---|---|---|
| 现象 | `{"name":"example.com","query_type":1,"edns0_enabled":true}`（层 schema `udp_payload_size` 默认 0）→ **ARCOUNT=0、无 OPT、报文与未启用 EDNS0 逐字节相同** | 本车道实测（§0.1）；`dns_edns0.pcap` 与 `dns_smoke_01.pcap` 同 71B |
| 根因 | `buildDNSQueryWithEDNS0:606-608`：`if udpPayloadSize == 0 { return base }` **在写 OPT 之前早退** | `dns.go:601-641` |
| 对照 | **多问路径无此分支**：`layer_gen.go:62-64` → `optWireRR(0, …)` → `:679-681` size=0 回退 **4096** → OPT 落线（实测 `edns0_multiq_no_size` ARCOUNT=1、len 34） | 本车道实测 |
| 对照 2 | **响应路径同无此分支**：`buildDNSResponseGeneral:812-814` → 同回退 | `dns.go:812-814` |
| 影响 | **同一 `edns0_enabled:true` 配置在单问 vs 多问路径行为不一致**；用例 `dns_edns0` 的 `summary` 声称 "edns0_enabled→附加节ARCOUNT=1" 但**实测 ARCOUNT=0**，`notes` 称 "RFC 6891 OPT" 亦不成立 | §9 表 #7 |
| 为何未被测出 | 该例 `expect` **只断言 `dns.qry.name`**（1 条），**未断言 `dns.count.add_rr`/ARCOUNT/OPT 存在**——**假绿**（测试点选错，非断言写错） | `cases/dns.json` 第 7 例 |
| 单元测试侧 | `TestF2_DNSPlan_EDNS0EmitsOPTRR`（`dns_fix_test.go:80`）**显式传 `UDPPayloadSize: 4096`**，故走的是"非早退"分支，绿；`TestBuildDNSQuery_EDNS0Disabled`（`dns_testpoints_test.go:707`）传 size=0 **且 edns0 走的是 `buildDNSQueryWithEDNS0`**，断言的是"无 OPT"——**两条测试都不覆盖"edns0_enabled + size 缺席"这一真实配置形状** | 单测实证 |
| 修复建议 | `buildDNSQueryWithEDNS0` 的早退条件改为 `if !edns0 { return base }`，size=0 时回退 4096（与 `optWireRR` 同口径）；**修后须重跑后钉**：`dns_edns0` 帧长 71→82、ARCOUNT 0→1，`packet_count` 不变 | — |

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | **无连接**（UDP 单次请求/响应，RFC 1035 §4.2.1）；TCP 载体为可选长连接（§4.2.2/RFC 7766） | 场景①–⑰ | `DependsOn ["udp"]`（`registry.go:135`）；`TransportOn ["udp","tcp"]`；TCP 链上拒（`layer_gen.go:113-115`） | TCP 载体未接线 → G-DNS-2 |
| 2 | 命令/消息表 | 查询（QR=0）/响应（QR=1）两类；opcode=0（标准查询）唯一 | 全场景 | Flags 常量 `0x0100`/`0x8180\|rcode`（`layer_gen.go:65`、`dns.go:817`）；**opcode 不可配** | **显式不适用**（单 opcode 是合理收窄，UPDATE/NOTIFY 等 opcode 不在本版范围，§1 边界④） |
| 3 | 状态机 | 无状态（一次一问一答） | — | dns 层无状态；udp 层无握手 | **显式不适用**（无连接协议） |
| 4 | 字段表 | Header 6 键（§3.1）+ Question 3 键（§3.3）+ RR 5 键（§3.4）+ RDATA 12 类（§3.5） | 数据场景层 | 逐字段落码（§3 全表） | name 压缩零使用 → G-DNS-1 |
| 5 | 错误处理 | 6 类负例（§7）+ 9 个未入例拒绝分支（§7 表） | 负例 N-1…N-6 | `validateDNSConfig` 8 分支 + V9 范围门 + 静态复制门 + CheckProtoFlat | A′ 补例（§14） |
| 6 | 超时与活性 | **无保活概念**（无连接）；重传由客户端驱动（同 TxID 重发） | #18 | 无保活帧（正确）；#18 覆盖重传同 ID | 无 |
| 7 | NAT/代理/被动 | 无被动模式（客户端直发）；NAT 穿透为框架面 | — | 无 `sessions[]`；多流走 `flows` | **显式不适用** |
| 8 | 版本/方言 | EDNS0（RFC 6891）版本 0；DNSSEC（RFC 4033/4034）；无 profile 协商 | #7/#27/#28 | OPT version 恒 0（`optWireRR` 经 `appendRR` 写 TTL byte1=0）；EDNS0 扩展 RCODE 不实现 | **M-1**（EDNS0 单问早退）；扩展 RCODE 不适用（§1 边界⑤） |

**逐格重数（机读复算）**：8 行 × 1 结论列 = 8——**已覆 1**（行 6 超时与活性：无缺口）/ **立项 4**（行 1 TCP 载体 G-DNS-2、行 4 name 压缩 G-DNS-1、行 5 A′ 补例、行 8 M-1）/ **不适用 3**（行 2 opcode 单值、行 3 状态机、行 7 被动模式）。1 + 4 + 3 = 8 ✓

### 10.2 子表①：消息类型 × 终态矩阵（逐格已覆/立项/不适用）

| 消息 | T1 正常终态 | T2 配置拒绝 | T3 异常终态 |
|---|---|---|---|
| 单问查询 | 已覆（#1/#4/#19） | 已覆（#13 空名 / #17 超长 label） | 不适用（无连接，无 RST 概念） |
| 多问查询 | 已覆（#14） | 已覆（#2/#3 代表） | 不适用 |
| 单 RR 响应 | 已覆（#5/#20–#25/#27/#28） | 已覆（#12 rcode 越界） | 不适用 |
| 多 RR 响应 | 已覆（#15/#16） | 已覆（代表已覆） | 不适用 |
| 权威节响应 | 已覆（#6） | 已覆（代表已覆） | 不适用 |
| EDNS0 查询 | **未覆（#7 实测未生效 → M-1）** | 已覆（代表已覆） | 不适用 |
| TCP 载体 | **不适用**（链上拒） | 已覆（#11） | 不适用 |
| 动态多流 | 已覆（#8/#9/#10） | 已覆（#3） | 不适用 |

**逐格重数（机读复算）**：8 行 × 3 列 = 24 格——**已覆 14**（T1 列 6：单问/多问/单 RR/多 RR/权威/动态；T2 列 8：8 行的配置拒绝全部有代表例；T3 列 0）/ **立项 1**（**M-1**：EDNS0 行 T1）/ **不适用 9**（T1 列 1 = TCP 载体；T3 列 8 = 8 行的异常终态全部不适用）。6+8+0 + 1 + 1+0+8 = 14 + 1 + 9 = 24 ✓

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **26 行**，每行均有正例/负例落点或立项/不适用结论：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | QTYPE=A(1) | 覆（#1/#5/#15/#16） |
| 2 | QTYPE=NS(2) | 覆（#23） |
| 3 | QTYPE=CNAME(5)（作 RDATA） | 覆（#16） |
| 4 | QTYPE=SOA(6)（作 authority RDATA） | 覆（#6） |
| 5 | QTYPE=PTR(12) | 覆（#24） |
| 6 | QTYPE=MX(15) | 覆（#21） |
| 7 | QTYPE=TXT(16) | 覆（#22） |
| 8 | QTYPE=AAAA(28) | 覆（#4/#20/#26） |
| 9 | QTYPE=SRV(33) | 覆（#25） |
| 10 | QTYPE=NAPTR(35) | 覆（#29） |
| 11 | QTYPE=DS(43) | 覆（#27） |
| 12 | QTYPE=DNSKEY(48) | 覆（#28） |
| 13 | QTYPE=OPT(41) | 覆（多问路径，**单问路径 M-1 失效**） |
| 14 | **QTYPE 未列值（→ RDLEN=0）** | **A′ 立项**（`encodeRDATA:975-978` default 分支，今日无例） |
| 15 | QCLASS 缺省 IN=1 | 覆（全正例，class 缺席） |
| 16 | QCLASS 显式非 IN | **A′ 立项**（`Questions[].Class` 可配，今日无例） |
| 17 | 单问 | 覆（#1/#4/#5/#19/#20–#29） |
| 18 | 多问（QDCOUNT=2） | 覆（#14） |
| 19 | 单答 | 覆（#5/#20–#25/#27/#28） |
| 20 | 多答（ANCOUNT=2） | 覆（#15/#16） |
| 21 | 权威节非空（NSCOUNT=1） | 覆（#6） |
| 22 | 附加节非空（ARCOUNT=1，EDNS0） | 覆（多问路径）；**单问 M-1 待修** |
| 23 | 空名 RR（NAME → 0x00） | **A′ 立项**（`rrToWire:836-838` 有分支，今日无例） |
| 24 | 尾点 FQDN 域名 | **A′ 立项**（`splitLabels:589` 有守卫，今日无例） |
| 25 | 连续点空 label | **A′ 立项**（`splitLabels:581` 有无条件 append，今日无例） |
| 26 | DS digest 非 hex / DNSKEY key 非 base64 | **A′ 立项**（静默吞错分支，G-DNS-5） |

**逐行重数（机读复算）**：**已覆 18**（行 1–13、15、17–22 中除 M-1 外）/ **立项 8**（**M-1 2**：行 13 QTYPE=OPT、行 22 附加节非空——**两行是同一缺陷的两个角度**，其唯一用例 #7 是单问路径、EDNS0 未生效；**普通立项 6**：行 14 未知 QTYPE、行 16 非 IN class、行 23 空名 RR、行 24 尾点、行 25 连续点、行 26 解码吞错）/ **不适用 0**。18 + 8 + 0 = 26 ✓

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 递归解析 A/AAAA（浏览器/系统解析器） | #1/#4/#5/#20/#26 | 已覆 |
| 2 | CDN 别名链解析 | #16 | 已覆 |
| 3 | 多 A 负载均衡 | #15 | 已覆 |
| 4 | 邮件路由（MX） | #21 | 已覆 |
| 5 | SPF/DKIM 校验（TXT） | #22 | 已覆 |
| 6 | 区域委派（NS） | #23 | 已覆 |
| 7 | 反向解析（PTR，日志/审计） | #24 | 已覆 |
| 8 | 服务发现（SRV，SIP/LDAP） | #25 | 已覆 |
| 9 | DNSSEC 信任链（DS/DNSKEY） | #27/#28 | 已覆 |
| 10 | 号码/URI 映射（NAPTR） | #29 | 已覆 |
| 11 | NXDOMAIN 负缓存 | #6 | 已覆 |
| 12 | 大响应协商（EDNS0） | #7 | **未覆（M-1）** |
| 13 | 丢包重传 | #18 | 已覆 |
| 14 | 批量扫描/域名爆破 | #8/#9/#10 | 已覆 |
| 15 | 诊断工具多问单包 | #14 | 已覆 |
| 16 | DNS over TCP（区域传送/大响应） | — | **范围外，缺口 G-DNS-2**（链上当前拒绝；接线计划见 §14） |
| 17 | DNS over TLS/HTTPS（加密解析） | — | **范围外，缺口 G-DNS-3**（DoH 为独立协议；DoT 接线计划见 §14） |
| 18 | TSIG 报文认证 | — | **范围外，缺口 G-DNS-13**（需新增签名字段与校验路径） |
| 19 | AXFR/IXFR 区域传送 | — | **范围外，缺口 G-DNS-14**（需新增多轮 TCP 事务编排） |
| 20 | 动态更新（UPDATE，opcode=5） | — | **范围外，缺口 G-DNS-15**（需新增 opcode 与更新区段） |
| 21 | 真实 DNSSEC 签名/验签 | — | **范围外，缺口 G-DNS-16**（当前仅编码 DS/DNSKEY 结构字段） |

**逐行重数（机读复算）**：共 21 行——**已覆 14**（行 1–11、13–15）/ **立项 1**（**M-1**：行 12 大响应协商——其唯一用例 #7 是假绿）/ **不适用 6**（行 16–21）。14 + 1 + 6 = 21 ✓ 无映射无确认即缺口——本表零缺口。

### 10.5 三路对照与候选方案对比（§4.12–4.15 / §4.17）

三路：①**规范原文**（RFC 1035/6891/4033/4034/3596/2782/3401/7766，定"必须是什么"）；②**商业化软件实际行为**（**未取到**：真实 BIND/Unbound/Knot 的线字节未抓包核对；tshark 3.6.14 的 dissector 行为已实测，但那是**解析器**不是**生成器**对照 → G-DNS-11 待确认）；③**可靠开源实现思路**（`golang.org/x/net/dns/dnsmessage` 与 `miekg/dns` 的报文结构思路——只借鉴"label 长度前缀 + 0x00 终止"与"RR 五字段固定头"两条，不搬码）。三路一致点：Header 12B 布局、大端、label 编码、RR 固定头；**不一致点**：**name 压缩**（规范 §4.1.4 是 SHOULD 级优化，主流实现**都做**，本实现**不做**——合法但非最优，G-DNS-1）；**EDNS0 size 回退**（主流实现 `edns0_enabled` 即发 OPT、size 缺省用 4096 或 1232，本实现单问路径不发——**M-1 是缺陷不是设计选择**）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | 独立 `dns` 终结层（本版；ntp/snmp/syslog/mdns 同构先例） | 12 类 RR / EDNS0 / 多问多答 / 动态三字段可声明可断言；代价 = 一套层（已落码 991 行） | **采用**（已落码） |
| B | 直接 udp 层 + 顶层 payload（手工 hex 载荷） | 无字段级断言、无动态、无 validator → 29 例中 25 例不可表达 | **否决** |
| C | 复用 `doh` 的 DNS wire 编码器（`doh/builder.go:205 encodeWire`） | 两包各自独立演化（doh 有 base64url/HTTP 映射，dns 无），共享会引入无谓耦合；且 doh 未导出该函数 | **否决** |
| D | 合并进 `mdns` 层（同为 DNS 报文格式） | mdns 有多播/组播组校验（`validateMulticastGroup`）、TTL=0 语义、NSEC——与单播 DNS 语义分叉，合并会把两套校验搅在一起 | **否决**（各自独立层是现状） |

## 11. P2 D-DNS-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 状态说明：实现已落码（`internal/protocol/dns/` 六文件），本 P2 条目为 P-PIPE 文档轨对既有实现的**逆向定稿**（as-built 定稿），供门1 批准后作为后续改动的唯一入口；P4 在本协议内为"缺口收敛"（§14），不另开新层。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（`:2231-2350` + `:1693`） | `DNSConfig`（15 字段）+ `DNSQuestion`（3）+ `DNSRR`（21）+ `FlowSpec.DNS` 槽位 | —（共享文件） |
| `trafficgen/internal/protocol/dns/dns.go` | 线编码 + planner：`Planner.Validate/Plan`、`validateDNSConfig`、`validateRRFamily`、`buildDNSQuery`、`buildDNSResponse`、`buildDNSQueryWithEDNS0`、`buildDNSMessage`、`appendRR`、`buildDNSResponseGeneral`、`rrToWire`、`encodeRDATA`、`encodeDomainName`、`splitLabels`、`prefixTCPLength`、`optWireRR`、`appendCharString`、`dnsQueryNames` | 991 |
| `trafficgen/internal/protocol/dns/layer_gen.go` | 终结层生成器（`RegisterLayerGenerator` + `RegisterLayerValidator`，`init()`）+ TCP 载体显式拒 | 118 |
| `trafficgen/internal/protocol/dns/dns_test.go` | 基础 planner 测试 | 219 |
| `trafficgen/internal/protocol/dns/dns_fix_test.go` | F1–F4 对抗回归（TxID 可配/EDNS0/族匹配/长度门） | 263 |
| `trafficgen/internal/protocol/dns/dns_coverage_test.go` | 覆盖率补充（含 EDNS0 响应侧 DO 位） | 1050 |
| `trafficgen/internal/protocol/dns/dns_testpoints_test.go` | 测试点全集（含 `TestDNSPlan_EDNS0Query` 历史声明） | 854 |
| 接线 6 件 | registry 注册（`layers/registry.go:134`，14 键）/ translate 层内分支（`chain_planner_translate.go:1957`）/ convert 子配置搬运（`strategy_convert.go:759`，**仅 legacy flat 路径**）/ CheckProtoFlat presence 分支（`strategy_convert.go:8650`）/ protocols 准入（`protocols.go:38`）/ 缺省端口 53（`chain_planner.go:1033`）+ 动态 allowlist（`layer_dyn.go:37`） | — |

> **注**：`dns.go` 的 `Planner`（legacy 路径）与 `layer_gen.go` 的 `DNSGenerator`（链路径）**共享同一批 builder 函数**（`layer_gen.go:14-16` 注释明写"事件字节复用 legacy builders，线输出与 legacy 逐字节一致"）。`chain_planner_dns_test.go` 的 `assertByteIdentical` 对 7 个场景锁定该等价性。

### 11.2 接口签名

- `Planner.Validate(spec core.FlowSpec) error`（`dns.go:61`）：IP 解析 + DstPort 缺省 53 + `validateDNSConfig`（**注意 `spec` 是值拷贝，默认化丢失**，`Plan` 内重做，`:206-208`）。
- `Planner.Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`:198`）：legacy 路径，`transport=="tcp"` 时走 `prefixTCPLength`。
- `validateDNSConfig(spec) error`（`:87`）：**两条路径共用的配置校验**（legacy `Validate` 与链 `RegisterLayerValidator` 都调它，`layer_gen.go:106-107`）——8 个拒绝分支。
- `DNSGenerator.Name() "dns"` / `GenEvents()` 返回自身 / `EmitEvent` 未接线显式错（`layer_gen.go:97-99`，防误调）/ `Generate` 逐消息 `EmitMsg`（`:29-89`）。

### 11.3 数据结构

`DNSConfig{Domain, QueryType, IsResponse, ResponseIP, TxID, EDNS0Enabled, UDPPayloadSize, DnssecOK, Transport, RCode, TTL, Questions[], Answers[], Authority[]}`（`types.go:2231-2283`）；`DNSQuestion{Name, Type, Class}`（`:2287-2291`）；`DNSRR{Name, Type, Class, TTL, IP, Target, Preference, Text, MName, RName, Serial, Refresh, Retry, Expire, Minimum, Priority, Weight, Port, Order, Flags, Service, Regexp, KeyTag, Algorithm, DigestType, Digest, KeyFlags, Protocol, PublicKey}`（`:2308-2350`，**28 字段**）。

### 11.4 主流程

层链配置 → `ValidateLayers`（registry Fields 14 键 allowlist + V9 范围门）→ translate（层 config → `spec.DNS`，含动态对象按 `FlowIndex` 直解，`chain_planner_translate.go:1957-2020`）→ 层校验器 `validateDNSConfig` → `ChainPlanner.drive` → `DNSGenerator.Generate`（`Meta.DNS` = `spec.DNS`）→ 逐事件 `EmitMsg` → udp 层生成器（每事件一 datagram）→ worker → writer（PCAP/NIC）。

### 11.5 错误分支

`validateDNSConfig` 8 分支（`dns.go:90/98/104/114/118/129/133/159/162/165/186/189/192`）+ `validateRRFamily` 3 分支 + 框架 V9 范围门（`response_code`）+ 静态复制门 + CheckProtoFlat presence 门，全部传 task error（零假成功——3 例在案负例实测 0 帧）。**EDNS0 的 size=0 早退是静默降级而非报错**（M-1）。

### 11.6 性能边界

见 §6（事件线性产出、per-flow 局部状态、无跨流共享、无锁；`dnsQueryNames` 的配置规模线性分配已登记；吞吐数字待 P4 基准）。

### 11.7 与现有逻辑的冲突点

- **`CheckProtoFlat` 有 dns 分支**（`strategy_convert.go:8650`）——顶层 `dns` 子映射 presence 判死（空 map 也死），**与 ocpua/moxa 的"无分支"不同，本协议此项已合规**。
- **`convert_proxy.go:55` 的 `"dns": true`** 表示 **legacy flat 路径仍接受顶层 `dns` 子映射**（`strategy_convert.go:759` 解析）——**该路径与链路径并存**，但 **schema 层 `CheckProtoFlat` 在 create 期先判死**（`schema/semantic.go:130`），故 **MCP 侧不可达**；引擎直调（单测）可达（`flat_dstport_default_test.go`、`strategy_convert_equivalence_test.go` 即走此路径）。**这是"判死已生效但旧解析器未删"的过渡态**，登记为 G-DNS-12。
- 动态 allowlist：`dns` 行开 `name`/`query_type`/`txid` 三键（`layer_dyn.go:37`）；`name` 走 string 面（`fixed/list/pattern`，`inc/rand` 拒，`:380-399`）；`query_type`/`txid` 走 int 面（`pattern` 拒，`:400-402`）；其余 11 键对象即 `does not support dynamic`。
- registry `dns` 有 **Fields 14 键**（与生成表 127 层同代，机读逐键一致）→ 层内 14 键今日已可住。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 7 文件（`dns.go`/`layer_gen.go`/4 个 `_test.go`/`types.go` 段）+ 接线 6 处（registry/protocols/translate/convert/CheckProtoFlat/chain_planner）；不触及其他协议。cases 回滚 = 恢复 29 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：**非负例 23 例顶层键 = `{layers}`（+ 3 例动态带 `strategy_fc`），零顶层 `dns` 子映射**；1 例负例**故意**带 `{layers, dns:{}}`（presence 判死对象）；目标形状见 §2 样例 | §12.1；`cases/dns.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 dns 流量模板；任务 = 多策略合跑 + 总量封顶；多流走 `strategy_fc`/`flow_control`；框架语义未动 | 设计 §2 样例；#8/#9/#10 |
| §3 五件套 | 见 §12.3 强制展开：**会话表豁免**（无连接协议）/ 事务序列（查询→可选响应）/ 关联（TxID 回显）/ 插入位置（终结层）/ 时间线 | §12.3 + §5 |
| §4 查规范 | RFC 1035 全篇 + 6891/4033/4034/3596/2782/3401/7766 + tshark 3.6.14 字段与 29 例 pcap 实测 + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["udp"]`（`registry.go:135`）；`TransportOn ["udp","tcp"]`；`OptionalOn ["tls"]`；反向**零协议依赖 dns**（机读 127 层实测）；6 类负例 + 9 未入例分支；失败传 task error（3 例 0 帧实测） | §2/§5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；吞吐数字标待 P4 基准，不写承诺；pcap/NIC 两路验收明写 + **NIC 今日零用例的诚实标注**） | §6 |
| §7 三份文档 | `docs/protocols/dns/{design,testcase}.md` v1.0.0 + D-DNS-1（§11）+ T-DNS（testcase §2，29 ID）+ 历史层 `docs/design/backend/13-DNS-ICMP-ARP实现.md` | 修订记录 |
| §8 设计先行 | 本版为批次二 as-built（实现与用例**先于**本版文档存在）；门1 获批 = 本契约定稿 = 后续改动唯一入口 | 提交序 |
| §9 测试三源 | 三源 = RFC 条文 + D-DNS-1（§11）+ tshark 3.6.14 字段与 **29 例 pcap 实测**（**88 条字段断言逐条复核 0 失配**，§0.1）；29 ID 逐项回指；存量审计去向 `docs/protocols/dns/testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审（本版自审见修订记录）+ 收官隔离复审；红先绿后 | 自审日志 |
| §11 白话 | 首节白话一句先行 | 本文首节 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（框架 allowlist）；业务字段 3 开（`name`/`query_type`/`txid`）+ 11 关，逐个列理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `dns` 已在 `registry.go:134` 注册（**不新增层**）；生成表 127 层同代（`fields` 14 键与 registry 逐键一致，机读实测）；**P4 若改 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `dns.*` + `udp.*` 双通道 → 先跑后钉；pcap 落 `/tmp/mcp-pcaps/dns/` | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 项 | 值 |
|---|---|
| 例数 | **29**（23 正 + 6 负） |
| 非负例顶层键分布 | `{layers}` ×20 + `{layers, strategy_fc}` ×3（#8/#9/#10）→ **零顶层 `dns` 子映射、零顶层四元组、零 `count`** |
| 负例顶层键分布 | `{layers, dns}` ×1（#2，**presence 判死对象**）+ `{layers}` ×4（#11/#12/#13/#17）+ `{layers, strategy_fc}` ×1（#3 静态复制例带 `strategy_fc{flows:2}`）——**合计 6** ✓ |
| 层形 | `[ip,udp,dns]` ×29（**全 29 例统一三层，含 v6 例——v6 地址住 `layers[0].ip.{src,dst}`**） |
| 负例 expect 形状 | 6/6 严格 `{expect_error, error_contains}`（**无 `notes`，干净**） |
| 正例 expect 形状 | `packet_count` ×4（#1/#4/#7/#14）+ `min_packets` ×19；`fields` 全 23 例有（共 88 条）；`expect.notes` ×10 + 例级 `notes` ×14 |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 已住 `layers[0].ip.{src,dst}`（29/29 显式写） |
| `src_port` | **0** | 已住 `layers[1].udp.src_port`（29/29 显式 12345） |
| `dst_port` | **0** | 已住 `layers[1].udp.dst_port`（29/29 显式 53） |
| `count` | **0** | 未用；多流走 `strategy_fc` |
| 顶层 `dns` 子映射 | **1**（#2 负例） | **故意保留作判死对象**（presence 负例形状：`layers` 与顶层空 `dns:{}` **并存**）——**非残留** |
| `strategy_fc` | **4**（#3/#8/#9/#10） | 顶层白名单内键（多流数量），**合规保留** |
| `flow_control` | **0** | 未用（`strategy_fc` 为其等价形状） |
| `response`（旧 `is_response` 别名） | **0** | 层内 `is_response`；legacy `getBoolWithFallback(sub,"is_response","response",…)` 仍接受别名（`strategy_convert.go:761`），**链路径无此别名** |
| `rcode`（旧 flat 名） | **0** | 层内改名 `response_code`（防与传输层 RCODE 混淆，D-DNS-1 决策 C） |
| `domain`（旧 flat 名） | **0** | 层内改名 `name`（D-DNS-1 flat 表） |

**结论**：**本协议存量非负例顶层零残留**——§1 门的动作 = ①**无旧键可删**（除 #2 的故意 presence 形状）；②收官自查行「非负例顶层键 = 0」**今日即成立**（机读：20 例仅 `{layers}` + 3 例 `{layers,strategy_fc}`，**无 `dns` 子映射、无四元组、无 count**）；③A′ 新增例全部沿用纯 layers 形（§13）。

> **注（2026-09-29 机读全仓统计）**：全仓 `cases/*.json` 中纯 `{layers}`（+可选 `strategy_fc`）形的协议远多于本协议，本协议只是其中之一，**并非"唯一"**。本协议的**特有事实**仅是"23/23 非负例今日即零残留"。

目标形状样例见 §2（顶层仅 `layers`；多流见 §2 第二例）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"dns":{}}` 今日**会被拒**（`CheckProtoFlat` 有 dns 分支，`strategy_convert.go:8650-8654`）→ **P4 应建该负例**（**存量 #2 即此形，已建**）✓。② 白名单外游离键判死（`unknown field`）——**顶层未知键通用门**今日**有**（批次一已扩列，`5c48ad5`/`300dfc4`）→ 可建，今日无例 → A′ 候选。③ 6 负例每条带锚词（已齐，§7）✓。④ 收官自查「非负例顶层键 = 0」**今日已成立**（§12.1）✓。

### 12.3 §3 强制展开：五件套

**会话表（豁免）**：**DNS 是无连接协议**（UDP 单次请求/响应，RFC 1035 §4.2.1）——**无 `sessions[]` 概念、无连接建立/保持/释放**。豁免理由：无连接状态可表；多流由策略级 `flows`（`strategy_fc`）承载，各流独立无交互。

**事务序列**：`t1` 查询（1 事件，`Up:true`）→ `t2` 响应（可选，`is_response:true` 时 1 事件，`Up:false`）。每事务四件事：**前置** = 无（无连接）；**触发** = 配置声明；**成功** = 事件产出并落 datagram；**失败** = Validate 期拒（§7）。多事务（`flows=N`）为 N 条独立 `t1(+t2)`，流间无先后依赖。

**关联关系**：**TxID 是唯一关联标识**（RFC 1035 §4.1.1）——查询与响应用同一 `cfg.TxID`（`buildDNSResponseGeneral:761-764`），实现即"响应回显查询 TxID"（MUST）。**无派生流**（诚实声明：单 datagram 承载全部消息，无 `driven_by`，无副连接）。

**插入位置**：终结层（`[ip,udp,dns]`，无中间层）；`OptionalOn ["tls"]` 声明 tls 可作底座但**未接线**（G-DNS-3）。

**时间线**：消息内严格顺序（Header → Question → Answer → Authority → Additional）；单流内查询先响应后、无交错；多流为 `flows=N` 顺序展开（各流内无交错）。

### 12.12 §12 强制展开：动态字段清单与序号算法

**四元组全开**（框架 allowlist `internal/core/layer_dyn.go` 头部实测：`ip`/`tcp`/`udp`/`eth`）：`ip.src`/`ip.dst`/`udp.src_port`/`udp.dst_port` 五策略（fixed/inc/rand/list/pattern）全开；保底 `DefaultSrcPort+i`（`strategy_convert.go:49`）；dst 动态与 53 缺省和平共处（显式/动态值非零即不触发补齐，`chain_planner.go:1012` 的 `isUniversalDefault` 守卫）。

**业务字段 14 键：3 开 + 11 关**（allowlist `layer_dyn.go:37` 实测 `"dns": {"name": true, "query_type": true, "txid": true}`）：

| 层.字段 | 开/关 | 面 | 覆盖用例 | 理由 |
|---|---|---|---|---|
| `dns.name` | **开** | string 面：`fixed`/`list`/`pattern`；**`inc`/`rand` 拒** | #8 | 查询域名逐流变（批量扫描；tls.sni 同款裁定） |
| `dns.query_type` | **开** | int 面：`fixed`/`inc`/`rand`/`list`；**`pattern` 拒** | #9 | 逐流查不同类型（http response_status_code 先例） |
| `dns.txid` | **开** | int 面：同 `query_type` | #10 | 逐流不同事务 ID（重传/去重语义需要） |
| `dns.is_response` | 关 | 布尔开关 | — | 开关语义逐流变无意义 |
| `dns.response_ip` | 关 | 响应静态值 | — | 响应内容非逐流值 |
| `dns.edns0_enabled` | 关 | 布尔开关 | — | 同上 |
| `dns.udp_payload_size` | 关 | 标量 | — | 同上 |
| `dns.dnssec_ok` | 关 | 布尔开关 | — | 同上 |
| `dns.transport` | 关 | 载体选择器 | — | 载体是链形状不是逐流值 |
| `dns.response_code` | 关 | 标量 | — | 同上 |
| `dns.ttl` | 关 | 标量 | — | 同上 |
| `dns.questions` | 关 | 数组（无动态形状） | — | 数组元素无 `strategy` 载体 |
| `dns.answers` | 关 | 数组（无动态形状） | — | 同上 |
| `dns.authority` | 关 | 数组（无动态形状） | — | 同上 |

**序号算法实读**：`parseLayerDyn`（`layer_dyn.go:78`）/ `TupleGenerator.Next`（`tuple_generator.go`）/ 保底自增（`strategy_convert.go:49` + worker 注入）/ allowlist 白名单（`layer_dyn.go:37`）；`dns` 有块（3 键），`layer_dyn.go:212-222` 的三分支 `set(where, lname, f, &out.DNS.Name/QueryType/TxID, v)`；形状门在 `:380-402`（name string 面 / query_type·txid 拒 pattern）。**逐流取值确定性**：按 `spec.FlowIndex` 直解（`chain_planner_translate.go:1971` `translateDNSDyn(cfg, rawDNS, spec.FlowIndex)`），到尾回绕由框架保证。

## 13. P3 对接清单（T-DNS 草稿输入；正文落 testcase 文件）

29 ID（23 正 + 6 负）+ 包数/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。A′ 候选 **17 例**：`dns_neg_transport_bogus`（transport 非法值）/ `dns_neg_rcode_planner`（planner 侧 rcode 分支，今日不可达）/ `dns_neg_q_empty_name`（questions[i] 空名）/ `dns_neg_rr_family`（answers/authority 族不匹配）/ `dns_neg_response_ip_family`（ResponseIP 族不匹配）/ `dns_neg_qname_254`（全名 254）/ `dns_unknown_qtype`（未知 TYPE → RDLEN=0）/ `dns_qclass_non_in`（非 IN class）/ `dns_edns0_size0_multiq`（多问 + size 缺席 → OPT 落线，**M-1 对照组**）/ `dns_edns0_dnssec_do`（DO 位断言）/ `dns_rr_empty_name`（空名 RR → 0x00）/ `dns_fqdn_trailing_dot`（尾点）/ `dns_double_dot`（连续点空 label）/ `dns_ds_bad_hex`（digest 非 hex 静默空）/ `dns_dnskey_bad_b64`（key 非 base64 静默空）/ `dns_default_port`（删 `dst_port` 不断言值）/ `dns_neg_mixed_family`（异族混写）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| **M-1** | **EDNS0 单问路径 `udp_payload_size=0` 早退**（`dns.go:606-608`）——`edns0_enabled:true` + size 缺席 → OPT 不落线，与多问/响应路径行为不一致；用例 #7 `dns_edns0` **假绿**（只断言 `dns.qry.name`，未断言 ARCOUNT） | **P4 必修**：①改早退条件为 `if !edns0`（size=0 回退 4096）；②用例 #7 补 `dns.count.add_rr=1` 断言；③重跑后钉（帧长 71→82，`packet_count` 不变） |
| G-DNS-1 | **name 压缩指针零使用**（`namePtrTo` 字段 + `appendRR:730-733` 的 `0xC000\|off` 分支已落码，**零调用方**）——产出报文合法但体积大于真实 DNS | A′ 候选：实现压缩（响应中 Answer NAME 指针指向 Question NAME，省 13B）或登记为已知体积差；在实现前按 G-DNS-1 登记缺口。今日不得声称支持压缩 |
| G-DNS-2 | **DNS-over-TCP 链上不可用**：`[ip,tcp,dns]` 补全通过但 Plan 期 8 包 0 payload；`transport:"tcp"` 被层校验器拒（`layer_gen.go:113-115`）；legacy `prefixTCPLength` 路径不在链上可达 | A′ 候选：接线 TCPGenerator 全握手（语义分叉需先裁定）；今日用例只覆盖“链上拒”（#11），并在 G-DNS-2 立项 |
| G-DNS-3 | **`OptionalOn ["tls"]` 已声明但 tls 载体未接线**（DoT，RFC 7858）；反向**零协议依赖 dns 层**（机读 127 层实测）——dns 不作他协议底座；`doh`/`mdns` 各带独立 wire 编码器不 import `protocol/dns`；`gre` 用例把 `{"dns":{}}` 当**内层载荷**（19 例） | ①DoT：A′ 候选或明确不解决；②"dns 作底座"的表述须以本表为准——**不存在**依赖 dns 层的协议层；`gre` 内层 dns 是**载荷复用**不是层依赖（G-DNS-3 的实质） |
| G-DNS-4 | **`encodeDomainName` 长度字节无守卫**（`byte(len(label))` 在 `:562` 直接截断，>255 静默回绕）——靠 validator 的 253/63 门前置拦截；**若 validator 被绕过（引擎直调 builder）仍会产畸形 QNAME** | A′ 候选：编码器内加守卫（防御性），缺口已登记 |
| G-DNS-5 | **DS `Digest` / DNSKEY `PublicKey` 解码失败静默吞错**（`dns.go:953-956`/`967-970` → 空 RDATA） | A′ 候选：改为拒绝，缺口已登记 |
| G-DNS-6 | **EDNS0 两套实现**（单问 `buildDNSQueryWithEDNS0` 手工 11B vs 多问/响应 `optWireRR` 经通用 RR）——M-1 的根因是两套实现语义分叉 | P4 随 M-1 一并收敛为单套（`optWireRR`） |
| G-DNS-7 | **rcode 越界双门字面不同**：框架 V9 门报 `out of range [0,15]`（N-4 命中此），`dns.go:104` 的 `dns rcode %d exceeds the 4-bit field (max 15)` **不可达** | A′ 候选：统一字面或删除不可达分支 |
| G-DNS-8 | **6 负例中仅 3 例有 pcap 留档**（`dns_neg_empty_name`/`dns_neg_long_domain`/`dns_neg_tcp`，均 0 帧）；`dns_neg_flat`/`dns_neg_rcode`/`dns_neg_static_copy` **无 pcap**——本车道**已用代码探针复现全部 3 例拒绝**（`BuildLayersPlanner` + `Validate` 实测命中锚词），但**未走完整 MCP 任务链路** | P4 补跑 3 例并留档 |
| G-DNS-9 | **结果文档 `trafficgen/docs/protocol-pcap-test/dns.md` 的 pcap 链接全死**：23/23 正例指向 `docs/protocol-pcap-test/dns/<id>.pcap`（**该目录不存在，0 个 pcap**，`git ls-files \| grep '\.pcap$'` = 0）；6 负例 `[pcap]()` 空链接。**注意本协议不适用 pcep G-PCEP-11 的"末次提交早于判死提交"口径**（`793dfee` 2026-09-19 **晚于** `0417be5` 2026-09-13）——本缺口是"**tracked 产物内容与仓库状态不符**"（死链），不是"过期未复跑" | **代码阶段**（P5 重跑套件后重生成该产物）；本版**不删不改**（tracked 产物，删除属 P5 动作）；在此之前读者不得据其 29/29 判断套件已复跑 |
| G-DNS-10 | **两个“不可表达”值**：① `TxID=0` 无法表达（0 → 0x1234 回退，`dns.go:379-381`）；② `TTL=0` 无法表达（三级回退到 300，`rrToWire:824-830`） | A′ 候选：增加显式 presence 开关，缺口已登记 |
| G-DNS-11 | **第三源未取到**：真实 BIND/Unbound/Knot 生成器的线字节未抓包对照（tshark dissector 已实测，但那是解析侧）；RFC 逐条条款号未逐一标注到行 | 待确认：抓真实解析器请求对照，或逐条补 RFC 条款号 |
| G-DNS-12 | **legacy flat 路径未删**：`convert_proxy.go:55` 的 `"dns": true` + `strategy_convert.go:759` 的顶层 `dns` 子映射解析器仍在（引擎直调可达），而 schema 层 `CheckProtoFlat` 已判死（MCP 不可达）——"判死已生效但旧解析器未删"的过渡态 | P4 裁定：删旧解析器（破坏 `flat_dstport_default_test.go`/`strategy_convert_equivalence_test.go`）或登记为兼容层 |
| G-DNS-13 | **TSIG 报文认证未实现**：当前没有签名字段或校验路径，不能声称覆盖 TSIG | P4/P5 候选：补签名字段、时间窗与校验路径 |
| G-DNS-14 | **AXFR/IXFR 区域传送未实现**：当前 TCP 链上载体不可用，也没有多轮区域传送编排 | P4/P5 候选：先接线 TCP 载体，再补多轮事务 |
| G-DNS-15 | **动态更新（UPDATE，opcode=5）未实现**：当前没有更新区段语义或 opcode=5 生成路径 | P4/P5 候选：补 opcode 与更新区段 |
| G-DNS-16 | **真实 DNSSEC 签名/验签未实现**：DS/DNSKEY 仅编码结构字段，不提供密码学签名或验证 | P4/P5 候选：补签名与验签路径 |

## 15. 修订记录

- v1.0.0（2026-09-29）：P-PIPE 文档轨批次二 #108 as-built 定稿。本协议**无旧编号设计文档**（§0 沿革），本版承 `docs/CODE_DESIGN.md` D-DNS-1 + 四条补遗的裁定与用例编号体系；29 例存量逐条机读对齐（§9，包数 23/23 一致、**88 条字段断言 0 失配**）；§12.1/12.3/12.12 强制展开 + 12-P2；D-DNS-1 as-built 定稿（§11）；**M-1（EDNS0 单问路径 size=0 早退 → 用例 #7 假绿）confirmed finding**（§9.2）；缺口 **M-1 + G-DNS-1…G-DNS-16**。自审 3 轮，末轮干净。
