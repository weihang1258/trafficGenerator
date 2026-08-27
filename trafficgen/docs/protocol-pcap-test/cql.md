# cql Pcap Test Results

Cases: 17 — pass 1, fail 5, error 11

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| cql_auth_empty_sasl | S3: AUTHENTICATE, empty AUTH_RESPONSE boundary, AUTH_SUCCESS | error | 0 | `` |
| cql_connect | S11: TCP 9042 connect without application events | error | 0 | `` |
| cql_error_server | S6: ERROR response with stable generic SERVER_ERROR body | error | 0 | `` |
| cql_ipv6 | S7: IPv6 CQL v4 startup/query transport | error | 0 | `` |
| cql_length_boundary | S10: zero-length OPTIONS body and nine-byte frame | error | 0 | `` |
| cql_multi_session | S9: two independent CQL sessions | error | 0 | `` |
| cql_neg_length | N4: truncated native frame rejected | fail | 0 | `` |
| cql_neg_limit | N6: frame over message limit rejected | fail | 0 | `` |
| cql_neg_opcode | N3: unknown opcode rejected | fail | 0 | `` |
| cql_neg_state | N5: QUERY before STARTUP/READY rejected | fail | 0 | `` |
| cql_neg_udp | N1: UDP carrier rejected | pass | 0 | [pcap]() |
| cql_neg_version | N2: unsupported protocol profile rejected | fail | 0 | `` |
| cql_options_supported | S2: OPTIONS and SUPPORTED capability map | error | 0 | `` |
| cql_prepare_execute | S5: PREPARE and EXECUTE request framing | error | 0 | `` |
| cql_query_void | S4: QUERY mutation and RESULT VOID with READY boundary | error | 0 | `` |
| cql_v4_startup_ready | S1: CQL v4 STARTUP then READY | error | 0 | `` |
| cql_v5_tracing | S8: CQL v5 profile and tracing request flag | error | 0 | `` |

## Failures

### cql_auth_empty_sasl — S3: AUTHENTICATE, empty AUTH_RESPONSE boundary, AUTH_SUCCESS

generate: failed to start any strategy (last failure: layers: layers: generator not implemented for layer "cql")

### cql_connect — S11: TCP 9042 connect without application events

generate: failed to start any strategy (last failure: layers: layers: generator not implemented for layer "cql")

### cql_error_server — S6: ERROR response with stable generic SERVER_ERROR body

generate: failed to start any strategy (last failure: layers: layers: generator not implemented for layer "cql")

### cql_ipv6 — S7: IPv6 CQL v4 startup/query transport

generate: failed to start any strategy (last failure: layers: layers: generator not implemented for layer "cql")

### cql_length_boundary — S10: zero-length OPTIONS body and nine-byte frame

generate: failed to start any strategy (last failure: layers: layers: generator not implemented for layer "cql")

### cql_multi_session — S9: two independent CQL sessions

generate: failed to start any strategy (last failure: layers: layers: generator not implemented for layer "cql")

### cql_neg_length — N4: truncated native frame rejected

rejected but error "failed to start any strategy (last failure: layers: layers: generator not implemented for layer \"cql\")" does not contain "length"

### cql_neg_limit — N6: frame over message limit rejected

rejected but error "failed to start any strategy (last failure: layers: layers: generator not implemented for layer \"cql\")" does not contain "limit"

### cql_neg_opcode — N3: unknown opcode rejected

rejected but error "failed to start any strategy (last failure: layers: layers: generator not implemented for layer \"cql\")" does not contain "opcode"

### cql_neg_state — N5: QUERY before STARTUP/READY rejected

rejected but error "failed to start any strategy (last failure: layers: layers: generator not implemented for layer \"cql\")" does not contain "state"

### cql_neg_version — N2: unsupported protocol profile rejected

rejected but error "failed to start any strategy (last failure: layers: layers: generator not implemented for layer \"cql\")" does not contain "version"

### cql_options_supported — S2: OPTIONS and SUPPORTED capability map

generate: failed to start any strategy (last failure: layers: layers: generator not implemented for layer "cql")

### cql_prepare_execute — S5: PREPARE and EXECUTE request framing

generate: failed to start any strategy (last failure: layers: layers: generator not implemented for layer "cql")

### cql_query_void — S4: QUERY mutation and RESULT VOID with READY boundary

generate: failed to start any strategy (last failure: layers: layers: generator not implemented for layer "cql")

### cql_v4_startup_ready — S1: CQL v4 STARTUP then READY

generate: failed to start any strategy (last failure: layers: layers: generator not implemented for layer "cql")

### cql_v5_tracing — S8: CQL v5 profile and tracing request flag

generate: failed to start any strategy (last failure: layers: layers: generator not implemented for layer "cql")

