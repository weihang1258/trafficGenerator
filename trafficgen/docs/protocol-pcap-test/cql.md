# cql Pcap Test Results

Cases: 17 — pass 17, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| cql_auth_empty_sasl | S3: AUTHENTICATE, empty AUTH_RESPONSE boundary, AUTH_SUCCESS | pass | 10 | [pcap](cql/cql_auth_empty_sasl.pcap) |
| cql_connect | S11: TCP 9042 connect without application events | pass | 7 | [pcap](cql/cql_connect.pcap) |
| cql_error_server | S6: ERROR response with stable generic SERVER_ERROR body | pass | 8 | [pcap](cql/cql_error_server.pcap) |
| cql_ipv6 | S7: IPv6 CQL v4 startup/query transport | pass | 11 | [pcap](cql/cql_ipv6.pcap) |
| cql_length_boundary | S10: zero-length OPTIONS body and nine-byte frame | pass | 8 | [pcap](cql/cql_length_boundary.pcap) |
| cql_multi_session | S9: two independent CQL sessions | pass | 18 | [pcap](cql/cql_multi_session.pcap) |
| cql_neg_length | N4: truncated native frame rejected | pass | 0 | [pcap]() |
| cql_neg_limit | N6: frame over message limit rejected | pass | 0 | [pcap]() |
| cql_neg_opcode | N3: unknown opcode rejected | pass | 0 | [pcap]() |
| cql_neg_state | N5: QUERY before STARTUP/READY rejected | pass | 0 | [pcap]() |
| cql_neg_udp | N1: UDP carrier rejected | pass | 0 | [pcap]() |
| cql_neg_version | N2: unsupported protocol profile rejected | pass | 0 | [pcap]() |
| cql_options_supported | S2: OPTIONS and SUPPORTED capability map | pass | 9 | [pcap](cql/cql_options_supported.pcap) |
| cql_prepare_execute | S5: PREPARE and EXECUTE request framing | pass | 9 | [pcap](cql/cql_prepare_execute.pcap) |
| cql_query_void | S4: QUERY mutation and RESULT VOID with READY boundary | pass | 12 | [pcap](cql/cql_query_void.pcap) |
| cql_v4_startup_ready | S1: CQL v4 STARTUP then READY | pass | 9 | [pcap](cql/cql_v4_startup_ready.pcap) |
| cql_v5_tracing | S8: CQL v5 profile and tracing request flag | pass | 11 | [pcap](cql/cql_v5_tracing.pcap) |
