# DOH（DNS over HTTPS，基于 HTTPS 的 DNS）测试用例契约

> 版本：v1.0.0（设计阶段）  
> 日期：2026-08-20  
> 配套设计：`docs/protocol-designs/66-doh-design.md`  
> 机器契约：`trafficgen/test/protocol_pcap/cases/doh.json`  
> 状态：`doh` 层尚未注册；本文定义实现后的 PCAP（抓包文件）/NIC（网卡）断言，不宣称当前 suite（测试套件）可运行。

## 1. 测试原则和未注册边界

用例从设计 §2–§8 逐项派生，共 20 个唯一语义 ID：14 个正例和 6 个负例。当前 JSON 只保留一个不计入语义覆盖的注册前置占位 `doh_neg_unregistered`，其 `expect` 必须 `expect_error=true`、`error_contains="unknown layer"`；注册后移除占位，再按本文 §2 顺序加入 20 个语义用例。

DOH carrier（载体）为 HTTP/1.1 POST/GET、HTTP/2、HTTP/3/QUIC 和 TLS opaque（不可解密）；DNS body 是 RFC 1035 wire format（线格式）。无 TLS key log（密钥日志）或解密 fixture 时，只可断言 carrier、方向、端口、地址族、frame/record 长度；不可声称加密内容中的 HTTP/DNS 字段。动态 DNS ID、随机 label、端口、TLS/QUIC 标识使用 `presence`、`nonzero`、`same_as_packet`、`distinct`，不硬编码。

## 2. 原子用例索引

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

## 3. 正例逐项断言契约

1. **`doh_post_ipv4_http11`**：使用 IPv4 `192.0.2.66`→`198.51.100.66`、TCP 443，断言 HTTP POST `/dns-query`、`Content-Type: application/dns-message`、Accept、Content-Length 等于 DNS body bytes，响应 DNS ID `same_as_packet`，`packet_count=8`。
2. **`doh_get_ipv4_base64url`**：断言 GET 无 body，URI path 含无 `=` padding 的 base64url；解码后是 DNS Header/Question，禁止普通 Base64 字符，动态 ID 用 presence/nonzero，`packet_count=8`。
3. **`doh_post_ipv6_http11`**：独立 IPv6/TCP/443 fixture，断言 IPv6 地址族、POST、请求/响应 `application/dns-message` 和精确 Content-Length，不能继承 IPv4 地址，`packet_count=8`。
4. **`doh_get_ipv6_base64url`**：断言 IPv6 GET URI 的 base64url 解码结果与 DNS wire 一致、无 padding/body，响应 ID 与请求 same_as，`packet_count=8`。
5. **`doh_dns_wire_query_response`**：断言 12-byte DNS Header、QDCOUNT/Question、Answer RDATA 和 response RCODE；运行期 ID presence/nonzero，响应 `same_as_packet`，`packet_count=8`。
6. **`doh_content_length_exact`**：至少覆盖短 body 和长 body，断言 POST `Content-Length` 按编码 bytes 计算，不按字符、十六进制或 Base64 长度计算，`packet_count=8`。
7. **`doh_http2_tls_streams`**：TLS ALPN `h2`，断言 HEADERS/DATA、END_STREAM、两个 stream 的 method/path/content-type（解密 fixture 时）和 DNS ID/响应按 stream 匹配，不跨流拼接，`packet_count=12`。
8. **`doh_http3_quic_streams`**：QUIC/UDP 443、ALPN `h3`，断言两个独立 bidirectional stream、QUIC stream 分片重组、DNS ID 按流匹配；不套用 TCP SYN 断言，`packet_count=12`。
9. **`doh_tls_opaque_carrier`**：TLS 1.3 ClientHello/ServerHello、443 和 ALPN/记录方向可见时断言；无 key log 不断言加密 HTTP method、Content-Type、DNS ID 或 RCODE，`packet_count=8`。
10. **`doh_multi_session_isolation`**：至少两个 TCP 或 QUIC 会话，断言动态 DNS ID `distinct`、每会话 QNAME/响应关联、独立连接状态，不依赖全局包序，`packet_count=16`。
11. **`doh_multi_stream_interleaving`**：HTTP/2/3 多 stream 交错和分片，断言每流独立重组、END_STREAM、ID/Question/response matching，不能把 packet boundary 当 wire 字段，`packet_count=16`。
12. **`doh_rcode_and_question`**：覆盖 NOERROR、NXDOMAIN、SERVFAIL 等合法 DNS RCODE，断言 HTTP 200 不替代 DNS 成功语义、Question 与响应 ID matching，`packet_count=10`。
13. **`doh_pcap_nic_ipv4`**：同一 IPv4 明文或解密 fixture 分别输出 PCAP 与 NIC；断言 TCP 443、方向、HTTP header、DNS wire 可观察字段一致。NIC 过滤器推荐 `tcp port 443`，`packet_count=12`。
14. **`doh_pcap_nic_ipv6`**：同一 IPv6 fixture 分别输出 PCAP/NIC；可覆盖 TCP/443 或 UDP/443 carrier，断言地址族、方向、端口和可见 frame/HTTP/DNS 字段一致，`packet_count=12`。

没有 TLS/QUIC 解密证据时，不添加“HTTP method 可见”“DNS ID 固定”“签名/随机值特定”等断言；使用通用 `tcp`、`udp`、`tls`、`quic` 和稳定 raw frames。

## 4. 负例契约

每个负例必须在 planner/validator 失败并传播为 task error；不能产生成功 PCAP、`completed/0 packet` 或只有 TCP/HTTP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`。

| ID | 故障输入 | 目标 `error_contains` |
|---|---|---|
| `doh_neg_dns_wire` | DNS Header/Question/RR、计数、pointer 或父子 length 错误 | `dns`、`wire` 或 `length` |
| `doh_neg_http_method_content_type` | 非 POST/GET、错误 Content-Type 或响应媒体类型错误 | `method`、`content`、`type` 或 `http` |
| `doh_neg_uri_base64url` | GET URI segment 缺失、普通 Base64、padding、非法字符或解码截断 | `uri`、`base64` 或 `decode` |
| `doh_neg_content_length` | POST Content-Length 与 DNS body bytes 不一致、body 缺失/多余 | `length`、`body` 或 `content` |
| `doh_neg_carrier_port_family` | HTTP/2/3/TLS carrier 混用、443/UDP/TCP 或 IPv4/IPv6 族错误 | `carrier`、`port`、`tcp`、`quic` 或 `family` |
| `doh_neg_response_matching` | DNS ID、Question、stream 或 session 响应与请求不匹配 | `match`、`dns`、`stream` 或 `session` |

负例不能依赖随机值；错误传播必须保留原始原因，不能用通用“0 packets”替代验证错误。

## 5. 三方一致性和静态检查

1. 设计 §8 的 20 个 ID、本文 §2、注册后的 JSON 和审计必须保持同一组 ID、同一顺序：14 正例 + 6 负例；当前 JSON 另有一个 `doh_neg_unregistered` 占位。
2. 未来 14 个正例均有 `packet_count`/`min_packets`、carrier、方向和稳定 HTTP/DNS/frame 字段；6 个负例的 `expect` 只能有 `expect_error`、`error_contains`。当前未注册 JSON 只验证 placeholder（占位）结构。
3. POST body 必须是 DNS wire bytes，Content-Length 等于编码字节；GET 必须是无 padding 的 base64url，URI 字符数不替代 DNS wire 长度。
4. HTTP/2 按 stream、HTTP/3 按 QUIC stream 重组；禁止跨流拼接，TLS opaque 时不伪造明文字段。
5. DNS ID 与响应使用 `same_as_packet`，不同会话/流使用 `distinct`/`nonzero`/presence；不硬编码动态随机值。
6. 推荐默认地址为 `192.0.2.66`/`198.51.100.66`，端口 443；IPv4/IPv6、TCP/UDP carrier 必须分别断言，不能混用。
7. PCAP/NIC 使用同一 spec，比较可观察字段和方向；TCP 过滤器为 `tcp port 443`，HTTP/3 为 `udp port 443`，记录 checksum offload 边界。
8. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/doh.json` 应成功；当前数组只能含 `doh_neg_unregistered`，且 `proto=doh`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。

## 6. 实现后执行建议

注册 `doh` layer 后，先检查 JSON parser、ID 顺序、正负 expect 键集合、DNS wire offsets/length、POST Content-Length、GET base64url、HTTP/2/3 stream 边界和 carrier 错误传播，再运行 1–14 的 PCAP/NIC 正例和 15–20 的错误传播。若环境没有 TLS/HTTP/2/3 解码器，使用通用 TCP/UDP/TLS/QUIC 字段与 raw frames；不能将唯一 placeholder 运行结果报告为 DOH suite 通过。

## 7. 修订记录

- v1.0.0（2026-08-20）：建立 14 个 RFC 8484/1035 正例和 6 个严格负例，覆盖 POST/GET、`application/dns-message`、Content-Length、base64url、HTTP/1.1/2/3、TLS carrier、IPv4/IPv6、多会话/多流、PCAP/NIC 和错误传播；不修改 Go/MCP 实现。
