# coap Pcap Test Results

Cases: 16 — pass 15, fail 1, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| coap_block2_two_blocks | C-008：Block2 两块响应，SZX=3（128B），M=1 后续 M=0 | pass | 4 | [pcap](coap/coap_block2_two_blocks.pcap) |
| coap_con_get | C-001：CON GET /sensors/temp，ACK 2.05 回显 MID/Token | pass | 2 | [pcap](coap/coap_con_get.pcap) |
| coap_con_timeout_retransmit | C-005：CON GET 超时，初始包加 4 次重传共 5 包 | pass | 5 | [pcap](coap/coap_con_timeout_retransmit.pcap) |
| coap_content_format_accept | C-007：POST Content-Format=50、Accept=50，响应显式声明格式 | pass | 2 | [pcap](coap/coap_content_format_accept.pcap) |
| coap_delete_deleted | C-004：CON DELETE /devices/7，ACK 2.02 Deleted | pass | 2 | [pcap](coap/coap_delete_deleted.pcap) |
| coap_error_responses | C-010：业务错误覆盖 4.04、4.13、5.00，保持 MID/Token 关联 | pass | 6 | [pcap](coap/coap_error_responses.pcap) |
| coap_invalid_code | N-003：Code=0x1f 保留/非法，不得默认为 GET | pass | 0 | [pcap]() |
| coap_invalid_tkl | N-002：TKL=9，超过 Token 最大 8 字节应拒绝 | pass | 0 | [pcap]() |
| coap_invalid_version | N-001：固定头 Version=2（高两位 10）应拒绝 | pass | 0 | [pcap]() |
| coap_ipv6_get | C-011：IPv6 GET /sensors/temp，验证 IPv6 地址与 CoAP 字段 | pass | 2 | [pcap](coap/coap_ipv6_get.pcap) |
| coap_multi_session | C-012：两条独立 IPv4 4-tuple，会话 Token/MID/返回端口不串流 | fail | 2 | `coap/coap_multi_session.pcap` |
| coap_non_post | C-002：NON POST /events，Content-Format=50，JSON 负载 | pass | 1 | [pcap](coap/coap_non_post.pcap) |
| coap_observe_notifications | C-009：Observe 注册首响应和两次通知，含 CON 通知 ACK | pass | 5 | [pcap](coap/coap_observe_notifications.pcap) |
| coap_put_changed | C-003：CON PUT /devices/7，ACK 2.04 Changed | pass | 2 | [pcap](coap/coap_put_changed.pcap) |
| coap_uri_path_query | C-006：GET 多段 Uri-Path 与两个 Uri-Query | pass | 2 | [pcap](coap/coap_uri_path_query.pcap) |
| coap_uri_too_long | N-004：URI Path 超过实现上限，不得静默截断 | pass | 0 | [pcap]() |

## Failures

### coap_multi_session — C-012：两条独立 IPv4 4-tuple，会话 Token/MID/返回端口不串流

verify: count: got 2 packets, want >= 4; field udp.dstport: distinct values mismatch (want [5683 56565 56566]; missing [56566]; unexpected []); field udp.srcport: distinct values mismatch (want [56565 56566 5683]; missing [56566]; unexpected []); field coap.token: distinct values mismatch (want [01020304 05060708]; missing [01020304 05060708]; unexpected []); field coap.mid: distinct values mismatch (want [20481 24577]; missing [20481 24577]; unexpected [0(x2)])

