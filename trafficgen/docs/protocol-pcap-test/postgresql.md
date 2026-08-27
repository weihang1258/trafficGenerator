# postgresql Pcap Test Results

Cases: 16 — pass 16, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| kingbase_auth_success | postgresql dialect=kingbase — S3: Startup, authentication exchange, and Ready | pass | 11 | [pcap](postgresql/kingbase_auth_success.pcap) |
| kingbase_connect | postgresql dialect=kingbase — S1: TCP 54321 connect and normal termination | pass | 7 | [pcap](postgresql/kingbase_connect.pcap) |
| kingbase_ipv4 | postgresql dialect=kingbase — S6: IPv4 compatible session | pass | 11 | [pcap](postgresql/kingbase_ipv4.pcap) |
| kingbase_ipv6 | postgresql dialect=kingbase — S7: IPv6 compatible session | pass | 11 | [pcap](postgresql/kingbase_ipv6.pcap) |
| kingbase_length_boundary | postgresql dialect=kingbase — S9: minimum non-empty Startup parameters | pass | 8 | [pcap](postgresql/kingbase_length_boundary.pcap) |
| kingbase_multi_session | postgresql dialect=kingbase — S8: two independent compatible sessions | pass | 22 | [pcap](postgresql/kingbase_multi_session.pcap) |
| kingbase_neg_oversize | postgresql dialect=kingbase — N6: message over implementation limit is rejected | pass | 0 | [pcap]() |
| kingbase_neg_port | postgresql dialect=kingbase — N2: nonstandard destination port is rejected | pass | 0 | [pcap]() |
| kingbase_neg_profile | postgresql dialect=kingbase — N3: unknown wire profile is rejected | pass | 0 | [pcap]() |
| kingbase_neg_state | postgresql dialect=kingbase — N4: query before Ready is rejected | pass | 0 | [pcap]() |
| kingbase_neg_truncated | postgresql dialect=kingbase — N5: truncated Startup length is rejected | pass | 0 | [pcap]() |
| kingbase_neg_udp | postgresql dialect=kingbase — N1: UDP carrier is rejected | pass | 0 | [pcap]() |
| kingbase_query_error | postgresql dialect=kingbase — S5: Simple query error response and Ready | pass | 14 | [pcap](postgresql/kingbase_query_error.pcap) |
| kingbase_query_success | postgresql dialect=kingbase — S4: Simple query success outer semantics | pass | 16 | [pcap](postgresql/kingbase_query_success.pcap) |
| kingbase_startup | postgresql dialect=kingbase — S2: PostgreSQL-compatible Startup message | pass | 8 | [pcap](postgresql/kingbase_startup.pcap) |
| postgresql-query-basic | PostgreSQL (端口 5432) 冒烟：完整 TCP 握手 + 启动消息 → 认证 → 参数 → SELECT 1 查询 → 终止 | pass | 23 | [pcap](postgresql/postgresql-query-basic.pcap) |
