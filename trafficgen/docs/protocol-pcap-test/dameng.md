# dameng Pcap Test Results

Cases: 14 — pass 14, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| dameng_auth_success | S2: connect and authentication success | pass | 10 | [pcap](dameng/dameng_auth_success.pcap) |
| dameng_connect | S1: TCP 5236 connect event | pass | 8 | [pcap](dameng/dameng_connect.pcap) |
| dameng_ipv4 | S6: IPv4 authenticated SQL session | pass | 12 | [pcap](dameng/dameng_ipv4.pcap) |
| dameng_ipv6 | S7: IPv6 authenticated SQL session | pass | 12 | [pcap](dameng/dameng_ipv6.pcap) |
| dameng_length_boundary | S5: profile minimum non-empty payload boundary | pass | 12 | [pcap](dameng/dameng_length_boundary.pcap) |
| dameng_multi_session | S8: two independent authenticated sessions | pass | 20 | [pcap](dameng/dameng_multi_session.pcap) |
| dameng_neg_oversize | N6: message over implementation limit is rejected | pass | 0 | [pcap]() |
| dameng_neg_port | N2: nonstandard destination port is rejected | pass | 0 | [pcap]() |
| dameng_neg_profile | N3: unknown wire profile is rejected | pass | 0 | [pcap]() |
| dameng_neg_state | N4: SQL before authentication is rejected | pass | 0 | [pcap]() |
| dameng_neg_truncated | N5: truncated application message is rejected | pass | 0 | [pcap]() |
| dameng_neg_udp | N1: UDP carrier is rejected | pass | 0 | [pcap]() |
| dameng_sql_error | S4: SQL error response remains a distinct event | pass | 12 | [pcap](dameng/dameng_sql_error.pcap) |
| dameng_sql_success | S3: authenticated SELECT success | pass | 12 | [pcap](dameng/dameng_sql_success.pcap) |
