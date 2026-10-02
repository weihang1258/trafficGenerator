# cql Pcap Test Results

Cases: 30 — pass 30, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| cql_auth_empty_sasl | S3: AUTHENTICATE, empty AUTH_RESPONSE boundary, AUTH_SUCCESS | pass | 10 | [pcap](cql/cql_auth_empty_sasl.pcap) |
| cql_connect | S11: TCP 9042 connect without application events | pass | 7 | [pcap](cql/cql_connect.pcap) |
| cql_consistency_quorum | A' (G-CQL-7): consistency field — LOCAL_QUORUM (0x0006) encoded as a big-endian short | pass | 11 | [pcap](cql/cql_consistency_quorum.pcap) |
| cql_error_server | S6: ERROR response with stable generic SERVER_ERROR body | pass | 8 | [pcap](cql/cql_error_server.pcap) |
| cql_flags_tracing_s2c_warning | A' (G-CQL-7/G-CQL-6): frame flags — tracing 0x02 on a c2s request, warning 0x08 on an s2c response | pass | 11 | [pcap](cql/cql_flags_tracing_s2c_warning.pcap) |
| cql_ipv6 | S7: IPv6 CQL v4 startup/query transport | pass | 11 | [pcap](cql/cql_ipv6.pcap) |
| cql_length_boundary | S10: zero-length OPTIONS body and nine-byte frame | pass | 8 | [pcap](cql/cql_length_boundary.pcap) |
| cql_multi_round_query | A' (G-CQL-7/§3.15①): multi-round QUERY on one connection — two SELECT→RESULT rounds then READY | pass | 14 | [pcap](cql/cql_multi_round_query.pcap) |
| cql_multi_session | S9: two independent CQL sessions | pass | 18 | [pcap](cql/cql_multi_session.pcap) |
| cql_neg_auth_order | G-CQL-6: AUTH_RESPONSE without a preceding AUTHENTICATE is rejected | pass | 0 | [pcap]() |
| cql_neg_beta_flag_v4 | G-CQL-6: the v5-only beta flag 0x10 on a v4 profile is rejected | pass | 0 | [pcap]() |
| cql_neg_length | N4: truncated native frame rejected | pass | 0 | [pcap]() |
| cql_neg_limit | N6: frame over message limit rejected | pass | 0 | [pcap]() |
| cql_neg_missing_tcp | missing tcp carrier: [ip,cql] dies (DependsOn auto-complete must not mask it) | pass | 0 | [pcap]() |
| cql_neg_opcode | N3: unknown opcode rejected | pass | 0 | [pcap]() |
| cql_neg_presence_top_level_cql | presence: layers + top-level cql{} coexist dies | pass | 0 | [pcap]() |
| cql_neg_startup_missing_cql_version | G-CQL-6: STARTUP without the mandatory CQL_VERSION option is rejected | pass | 0 | [pcap]() |
| cql_neg_state | N5: QUERY before STARTUP/READY rejected | pass | 0 | [pcap]() |
| cql_neg_stray_count | stray top-level count with layers dies | pass | 0 | [pcap]() |
| cql_neg_stray_src_ip | stray top-level src_ip with layers dies | pass | 0 | [pcap]() |
| cql_neg_udp | N1: UDP carrier rejected | pass | 0 | [pcap]() |
| cql_neg_unknown_layer_field | unknown key in cql layer entry dies | pass | 0 | [pcap]() |
| cql_neg_v5_post_handshake_envelope | W2/G-CQL-3 (B2 transition): a v5 post-handshake message is rejected (needs the envelope) | pass | 0 | [pcap]() |
| cql_neg_version | N2: unsupported protocol profile rejected | pass | 0 | [pcap]() |
| cql_options_supported | S2: OPTIONS and SUPPORTED capability map | pass | 9 | [pcap](cql/cql_options_supported.pcap) |
| cql_prepare_execute | S5: PREPARE/EXECUTE requests after STARTUP/READY | pass | 11 | [pcap](cql/cql_prepare_execute.pcap) |
| cql_query_void | S4: QUERY mutation and RESULT VOID with READY boundary | pass | 12 | [pcap](cql/cql_query_void.pcap) |
| cql_stream_correlation | A' (G-CQL-7): non-zero stream correlation — two requests (stream 1/2), responses returned out of order (stream 2 first), each response stream matches its request | pass | 13 | [pcap](cql/cql_stream_correlation.pcap) |
| cql_v4_startup_ready | S1: CQL v4 STARTUP then READY | pass | 9 | [pcap](cql/cql_v4_startup_ready.pcap) |
| cql_v5_tracing | S8: CQL v5 handshake-only (OPTIONS/SUPPORTED/STARTUP/READY, unframed pre-handshake face) | pass | 11 | [pcap](cql/cql_v5_tracing.pcap) |
