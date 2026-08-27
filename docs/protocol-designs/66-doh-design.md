# DOH（DNS over HTTPS，基于 HTTPS 的 DNS）设计契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 状态：仅设计与 PCAP（抓包文件）用例契约；`doh` 层尚未注册，不修改 Go（编程语言）实现，不宣称当前 suite（测试套件）可运行。  
> 配套文件：`docs/protocol-designs/66-doh-testcase.md`、`trafficgen/test/protocol_pcap/cases/doh.json`  
> 规范基线：RFC 8484（DNS Queries over HTTPS）、RFC 1035（DNS wire format，DNS 线格式）、RFC 9110/9112（HTTP 语义与消息）、RFC 7540（HTTP/2）、RFC 9114（HTTP/3）、RFC 8446（TLS 1.3）。

## 1. 范围、证据等级和未注册边界

本设计定义 RFC 8484 的 DNS over HTTPS（DOH）请求/响应、HTTP POST/GET 两种映射、`application/dns-message` 媒体类型、`Content-Length`、GET 的 base64url（无填充 URL 安全 Base64）编码，以及 HTTP/1.1、HTTP/2、HTTP/3 和 TLS carrier（载体）。DNS body 必须是 RFC 1035 DNS wire message；DOH 不重新定义 DNS header、Question、Answer、Authority 或 Additional 的编码。

没有解密 TLS key log（密钥日志）、完整证书链或 HTTP/2/3 明文 fixture（固定样本）时，只断言 TCP/TLS 或 UDP/QUIC carrier、方向、端口、地址族、长度和可见 raw bytes；不得声称 HTTPS 内部 HTTP/DNS 内容已经解析。动态 DNS transaction ID（事务 ID）、查询名、随机值和 QUIC/TLS 标识使用 `presence`、`nonzero`、`distinct`、`same_as_packet`，不硬编码运行期随机值。

当前仓库没有注册 `doh` layer、planner（规划器）、validator（校验器）或生成器。`cases/doh.json` 只保留一个 `doh_neg_unregistered` 注册前置占位，必须 `expect_error=true` 且 `error_contains="unknown layer"`；占位不计入下文 20 个语义 ID。注册前拒绝、0 包或只有 TCP/HTTP 外壳不是 DOH 行为通过。

## 2. 推荐配置、层链和地址

推荐明文验证层链为 `[ip, tcp, http, doh]`；实现 HTTP/2/3/TLS 时，carrier 由 `doh` 配置声明并由对应 TLS/QUIC 层承载。题定默认地址为 IPv4 `192.0.2.66` 到 `198.51.100.66`，DOH HTTPS 端口为 TCP `443`。IPv6 用例必须显式使用独立 IPv6 地址，不从 IPv4 默认值推导。

```json
{
  "layers": [{"tcp": {}}, {"http": {}}, {"doh": {}}],
  "src_ip": "192.0.2.66", "dst_ip": "198.51.100.66",
  "src_port": 42066, "dst_port": 443,
  "doh": {
    "method": "POST", "uri": "/dns-query",
    "content_type": "application/dns-message",
    "dns_id": {"strategy": "rand", "range": [1, 65535], "seed": 6601},
    "qname": "www.example.test", "qtype": "A",
    "carrier": "http/1.1", "tls": true
  }
}
```

| 配置键 | 约束 |
|---|---|
| `method` | 只能为 `POST` 或 `GET`。POST body 是完整 DNS wire message；GET 将完整 wire message 编为无 `=` padding 的 base64url。 |
| `uri` | 默认 `/dns-query`；GET 的编码结果追加在 URI path，不能把普通 Base64、百分号编码或 query 文本当作 wire message。 |
| `content_type` | 请求和响应均为 `application/dns-message`；不得用 `application/dns`、`text/plain` 或 JSON 替代。 |
| `Content-Length` | HTTP/1.1 POST 的值必须等于 DNS body 的编码字节数；GET 不把 URI 字符数冒充 body 长度；HTTP/2/3 使用 DATA frame 长度和消息边界。 |
| `dns_id` | 16-bit DNS ID，运行期随机或递增；同一请求响应 `same_as_packet`，不同会话 `distinct`，不能硬编码。 |
| `qname`/`qtype` | Question 的 wire 编码遵循 RFC 1035；根名、大小写和 label 长度边界必须保留，不能用展示字符串长度替代编码长度。 |
| `response` | response DNS ID、Question 和响应语义与请求匹配；NXDOMAIN、SERVFAIL 等 RCODE 是合法 DNS 响应，不能仅以 HTTP 200 判定 DNS 成功。 |
| `carrier` | `http/1.1`、`http/2`、`http/3` 或 `tcp`（TLS opaque）；HTTP/2 使用 stream，HTTP/3 使用 QUIC stream，不能把多流数据跨流拼接。 |
| `tls`/`port` | HTTPS 默认 TCP 443；明文 HTTP 仅在显式 profile 中使用 80。TLS 未解密时只断言 TLS carrier，不能断言内部 method、header 或 DNS bytes。 |
| `session_id`/`flow_count` | 每会话独立 DNS ID、stream、keep-alive 状态和响应关联；多会话可以并行但不可共享 transaction 状态。 |
| `wire_fault` | 仅负例注入口：`dns_wire`、`http_method`、`content_type`、`uri_base64url`、`length`、`carrier`。 |

## 3. DNS wire message 与 POST 映射

DNS wire message 的固定 Header 为 12 bytes：Transaction ID、Flags、QDCOUNT、ANCOUNT、NSCOUNT、ARCOUNT 均为网络字节序。Question 使用 QNAME 的 length-prefixed label、零终止、QTYPE、QCLASS；Answer 等资源记录按 RFC 1035 的 NAME/TYPE/CLASS/TTL/RDLENGTH/RDATA 编码。未知或扩展记录不得借 HTTP JSON 结构代替。

POST 请求：

```text
POST /dns-query HTTP/1.1
Host: dns.example.test
Content-Type: application/dns-message
Accept: application/dns-message
Content-Length: <DNS wire bytes>

<DNS query wire message>
```

POST 响应必须是 HTTP 成功或明确 HTTP 错误状态加 `application/dns-message`（若有 DNS body）；HTTP status 200 不等于 DNS RCODE=NOERROR。`Content-Length` 只按 body bytes 计算，不能按 Unicode 字符、十六进制文本或 Base64 文本长度计算。HTTP/1.1 keep-alive 通过 Content-Length 或明确分块边界分隔事务，禁止把两个 body 粘成一个 DNS message。

DNS ID、Flags、计数、压缩 pointer、TTL、RDATA 和 query name 由 DNS wire 规则验证；没有固定 fixture 时，ID、nonce-like random label 和随机端口只作存在、非零、同包关联或跨会话不同断言。

## 4. GET 映射与 base64url

GET 请求将 DNS wire message 编码为 RFC 4648 base64url，去除 `=` padding，放入 `/dns-query` 后的 path segment；请求不得携带 POST body：

```text
GET /dns-query/<base64url(DNS wire message)> HTTP/1.1
Accept: application/dns-message
```

实现必须逐字节验证解码结果，再解析 DNS wire message。`+`、`/`、`=`、普通 Base64 字母表、空 segment、多余 segment、非法字符、解码后截断和 URI 中编码文本被当成 DNS body 都应失败。GET path 的 URI 字符长度不等于 DNS wire bytes，Content-Length 不能替代 base64url 解码后的长度检查；URI 过长时必须按声明的 HTTP/2/3 stream 规则处理，不静默截断。

GET 响应仍使用 `application/dns-message` 和 DNS wire response。缓存相关 header 不改变 DNS ID、Question、RCODE 或 response body 的语义；HTTP 404/400 等错误不得伪装成 DNS NOERROR。

## 5. HTTP/2、HTTP/3、TLS 和流边界

HTTP/2 使用 TLS ALPN（应用层协议协商）`h2`、明确 stream ID、HEADERS/DATA frame 和 END_STREAM；HTTP/3 使用 QUIC、ALPN `h3` 和独立 bidirectional stream。HTTP/2/3 的 HPACK/QPACK header 压缩在未解码时只断言 frame/stream 方向和长度；解码 fixture 才断言 `:method`、`:path`、`:authority`、`content-type`、`content-length`。

TLS 1.3 载体应断言 ClientHello/ServerHello、ALPN、握手方向、记录长度和 TCP 443；没有 key log 不断言加密后的 DNS ID、HTTP method 或媒体类型。HTTP/3 的 QUIC/UDP 443 与 TCP/443 是不同 carrier，不能将 TCP SYN 断言套到 HTTP/3。TLS/QUIC 加密长度不是 DNS wire 长度；只有解密后的 HTTP body 或稳定 raw fixture 才能做 DNS 字段断言。

多流测试至少建立两个 HTTP/2 stream 或 HTTP/3 QUIC stream，交错发送请求；每流独立保存 DNS ID、QNAME、response 和结束标志。多会话测试至少使用两个四元组/QUIC connection，断言响应不会跨流匹配。TCP 分段、HTTP/2 DATA 分片、QUIC stream 分片都必须先按各自 stream 重组，不能把 packet boundary 当协议字段。

## 6. IPv4/IPv6、PCAP/NIC 和边界

IPv4 用例断言 `ip.proto=6`（HTTP/1.1、HTTP/2/TLS TCP）或 `ip.proto=17`（HTTP/3/QUIC）、地址 `192.0.2.66`/`198.51.100.66`、TCP/UDP 443 和方向。IPv6 用例独立断言 `ipv6.nxt`、IPv6 源/目的地址、端口、校验和及 stream carrier，不能从 IPv4 fixture 继承地址。

PCAP（抓包文件）输出断言以太网/IP/TCP 或 UDP/QUIC carrier、三次握手（TCP 时）、TLS/ALPN（可见时）、HTTP/1.1 header 或 HTTP/2/3 frame（解密 fixture 时）、DNS wire Header/Question/RCODE。NIC（网卡）捕获必须使用同一 spec（规格）和端口过滤器：TCP profile 推荐 `tcp port 443`，HTTP/3 推荐 `udp port 443`，并记录 checksum offload（校验和卸载）边界。PCAP 与 NIC 只比较可观察字段，不硬编码运行期序列号、DNS ID 或随机 token。

至少覆盖：POST/GET、`application/dns-message`、Content-Length、base64url、HTTP/1.1/2/3、TLS opaque、IPv4/IPv6、多会话/多流、分片/粘连、NOERROR/NXDOMAIN 等 RCODE、PCAP/NIC 双输出和错误传播。

## 7. 错误处理、三方证据和完成定义

负例必须在 planner/validator 失败并传播为 task error，不能输出成功 PCAP、`completed/0 packet` 或只有 TCP/HTTP 外壳的假成功。负例执行期 `expect` 只能包含 `expect_error` 与 `error_contains`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `doh_neg_dns_wire` | DNS Header/Question/RR 截断、计数越界、非法 pointer 或 wire length | `dns`、`wire` 或 `length` |
| `doh_neg_http_method_content_type` | 非 POST/GET、错误 Content-Type、响应媒体类型不匹配 | `method`、`content`、`type` 或 `http` |
| `doh_neg_uri_base64url` | GET URI 缺 segment、普通 Base64、padding、非法字符或解码截断 | `uri`、`base64` 或 `decode` |
| `doh_neg_content_length` | POST Content-Length 与 DNS bytes 不同、body 缺失或多余 | `length`、`body` 或 `content` |
| `doh_neg_carrier_port_family` | HTTP/2/3/TLS carrier 混用、错误端口、TCP/UDP 或 IPv4/IPv6 族错误 | `carrier`、`port`、`tcp`、`quic` 或 `family` |
| `doh_neg_response_matching` | 响应 DNS ID、stream、Question 或会话与请求不匹配 | `match`、`dns`、`stream` 或 `session` |

正例的动态 DNS ID、随机 QNAME label、TLS/QUIC 随机值和序列号只用 `presence`、`nonzero`、`distinct`、`same_as_packet`；不得把随机运行期值写成固定常量。错误必须保留原始原因，不能用通用“0 packets”替代验证失败。

实现完成定义：注册 `doh` layer；逐字节生成并验证 RFC 1035 DNS wire；实现 RFC 8484 POST/GET、媒体类型、Content-Length、base64url；实现 HTTP/1.1、HTTP/2、HTTP/3/TLS carrier 和 stream 边界；planner→worker→PCAP/NIC output 完整传播正负结果；测试覆盖 IPv4/IPv6、多会话/多流、分片/粘连、动态 ID 关联和错误传播；未解密 TLS 不声称 HTTP/DNS 内容可见。

## 8. 20 个语义场景和 packet_count 映射

共 20 个唯一语义 ID：14 个正例和 6 个负例；顺序必须与 `66-doh-testcase.md` §2 及注册后的 `doh.json` 完全一致。当前 JSON 只有不计数的注册前置占位。

| # | ID | 类型 | 覆盖 | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `doh_post_ipv4_http11` | 正 | RFC 8484 POST、IPv4、HTTP/1.1、`application/dns-message` | 8 |
| 2 | `doh_get_ipv4_base64url` | 正 | RFC 8484 GET、无填充 base64url、IPv4 | 8 |
| 3 | `doh_post_ipv6_http11` | 正 | POST、IPv6、Content-Length 和响应媒体类型 | 8 |
| 4 | `doh_get_ipv6_base64url` | 正 | GET、IPv6、URI 解码后的 DNS wire | 8 |
| 5 | `doh_dns_wire_query_response` | 正 | DNS Header/Question/RR、ID same_as、RCODE | 8 |
| 6 | `doh_content_length_exact` | 正 | POST body bytes 与 Content-Length 精确相等 | 8 |
| 7 | `doh_http2_tls_streams` | 正 | TLS+h2、HEADERS/DATA、两个 HTTP/2 stream 隔离 | 12 |
| 8 | `doh_http3_quic_streams` | 正 | TLS+h3、QUIC/UDP 443、多 stream 隔离 | 12 |
| 9 | `doh_tls_opaque_carrier` | 正 | TLS 1.3/443 握手、ALPN 和不可见 DNS body 边界 | 8 |
| 10 | `doh_multi_session_isolation` | 正 | 多 TCP/QUIC 会话、动态 ID distinct、响应匹配 | 16 |
| 11 | `doh_multi_stream_interleaving` | 正 | HTTP/2/3 分片交错、按流重组且不跨流拼接 | 16 |
| 12 | `doh_rcode_and_question` | 正 | NOERROR/NXDOMAIN/SERVFAIL、Question/ID 关联 | 10 |
| 13 | `doh_pcap_nic_ipv4` | 正 | IPv4 PCAP/NIC、TCP 443、HTTP/DNS 可观察字段一致 | 12 |
| 14 | `doh_pcap_nic_ipv6` | 正 | IPv6 PCAP/NIC、TCP/UDP carrier、地址族一致 | 12 |
| 15 | `doh_neg_dns_wire` | 负 | DNS wire 结构、tag/计数/pointer/长度错误 | — |
| 16 | `doh_neg_http_method_content_type` | 负 | HTTP method 或 Content-Type 错误 | — |
| 17 | `doh_neg_uri_base64url` | 负 | GET URI/base64url/padding/解码错误 | — |
| 18 | `doh_neg_content_length` | 负 | Content-Length 与 body 字节不一致 | — |
| 19 | `doh_neg_carrier_port_family` | 负 | carrier、端口、TCP/UDP 和 IPv4/IPv6 族错误 | — |
| 20 | `doh_neg_response_matching` | 负 | DNS ID、Question、stream 或 session 响应不匹配 | — |

设计 §8、`66-doh-testcase.md` §2、注册后的 `doh.json` 必须保持同一组 20 个 ID、同一顺序、14 正例+6 负例；当前 JSON 另有一个不计数的 `doh_neg_unregistered`，且唯一预期为 `unknown layer`。

## 9. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 RFC 8484/1035 正例和 6 个严格负例，覆盖 POST/GET、媒体类型、Content-Length、base64url、HTTP/1.1/2/3、TLS carrier、IPv4/IPv6、多会话/多流、PCAP/NIC 和错误传播；不修改 Go/MCP（模型上下文协议，Model Context Protocol）实现。
