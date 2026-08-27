# coap Pcap Test Results

Cases: 16 — pass 0, fail 4, error 12

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| coap_block2_two_blocks | C-008：Block2 两块响应，SZX=3（128B），M=1 后续 M=0 | error | 0 | `` |
| coap_con_get | C-001：CON GET /sensors/temp，ACK 2.05 回显 MID/Token | error | 0 | `` |
| coap_con_timeout_retransmit | C-005：CON GET 超时，初始包加 4 次重传共 5 包 | error | 0 | `` |
| coap_content_format_accept | C-007：POST Content-Format=50、Accept=50，响应显式声明格式 | error | 0 | `` |
| coap_delete_deleted | C-004：CON DELETE /devices/7，ACK 2.02 Deleted | error | 0 | `` |
| coap_error_responses | C-010：业务错误覆盖 4.04、4.13、5.00，保持 MID/Token 关联 | error | 0 | `` |
| coap_invalid_code | N-003：Code=0x1f 保留/非法，不得默认为 GET | fail | 0 | `` |
| coap_invalid_tkl | N-002：TKL=9，超过 Token 最大 8 字节应拒绝 | fail | 0 | `` |
| coap_invalid_version | N-001：固定头 Version=2（高两位 10）应拒绝 | fail | 0 | `` |
| coap_ipv6_get | C-011：IPv6 GET /sensors/temp，验证 IPv6 地址与 CoAP 字段 | error | 0 | `` |
| coap_multi_session | C-012：两条独立 IPv4 4-tuple，会话 Token/MID/返回端口不串流 | error | 0 | `` |
| coap_non_post | C-002：NON POST /events，Content-Format=50，JSON 负载 | error | 0 | `` |
| coap_observe_notifications | C-009：Observe 注册首响应和两次通知，含 CON 通知 ACK | error | 0 | `` |
| coap_put_changed | C-003：CON PUT /devices/7，ACK 2.04 Changed | error | 0 | `` |
| coap_uri_path_query | C-006：GET 多段 Uri-Path 与两个 Uri-Query | error | 0 | `` |
| coap_uri_too_long | N-004：URI Path 超过实现上限，不得静默截断 | fail | 0 | `` |

## Failures

### coap_block2_two_blocks — C-008：Block2 两块响应，SZX=3（128B），M=1 后续 M=0

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: coap)

### coap_con_get — C-001：CON GET /sensors/temp，ACK 2.05 回显 MID/Token

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: coap)

### coap_con_timeout_retransmit — C-005：CON GET 超时，初始包加 4 次重传共 5 包

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: coap)

### coap_content_format_accept — C-007：POST Content-Format=50、Accept=50，响应显式声明格式

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: coap)

### coap_delete_deleted — C-004：CON DELETE /devices/7，ACK 2.02 Deleted

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: coap)

### coap_error_responses — C-010：业务错误覆盖 4.04、4.13、5.00，保持 MID/Token 关联

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: coap)

### coap_invalid_code — N-003：Code=0x1f 保留/非法，不得默认为 GET

rejected but error "failed to start any strategy (last failure: task validation failed: invalid protocol: coap)" does not contain "code"

### coap_invalid_tkl — N-002：TKL=9，超过 Token 最大 8 字节应拒绝

rejected but error "failed to start any strategy (last failure: task validation failed: invalid protocol: coap)" does not contain "token"

### coap_invalid_version — N-001：固定头 Version=2（高两位 10）应拒绝

rejected but error "failed to start any strategy (last failure: task validation failed: invalid protocol: coap)" does not contain "version"

### coap_ipv6_get — C-011：IPv6 GET /sensors/temp，验证 IPv6 地址与 CoAP 字段

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: coap)

### coap_multi_session — C-012：两条独立 IPv4 4-tuple，会话 Token/MID/返回端口不串流

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: coap)

### coap_non_post — C-002：NON POST /events，Content-Format=50，JSON 负载

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: coap)

### coap_observe_notifications — C-009：Observe 注册首响应和两次通知，含 CON 通知 ACK

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: coap)

### coap_put_changed — C-003：CON PUT /devices/7，ACK 2.04 Changed

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: coap)

### coap_uri_path_query — C-006：GET 多段 Uri-Path 与两个 Uri-Query

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: coap)

### coap_uri_too_long — N-004：URI Path 超过实现上限，不得静默截断

rejected but error "failed to start any strategy (last failure: task validation failed: invalid protocol: coap)" does not contain "uri"

