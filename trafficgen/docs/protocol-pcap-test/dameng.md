# dameng Pcap Test Results

Cases: 34 — pass 34, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| dameng_auth_error_then_close | S3b: auth error then clean close | pass | 11 | [pcap](dameng/dameng_auth_error_then_close.pcap) |
| dameng_auth_success | S2: connect and authentication success | pass | 10 | [pcap](dameng/dameng_auth_success.pcap) |
| dameng_close_clean | S6: full success order plus trailing close | pass | 13 | [pcap](dameng/dameng_close_clean.pcap) |
| dameng_connect | S1: TCP 5236 connect event | pass | 8 | [pcap](dameng/dameng_connect.pcap) |
| dameng_ipv4 | S6: IPv4 authenticated SQL session | pass | 12 | [pcap](dameng/dameng_ipv4.pcap) |
| dameng_ipv6 | S7: IPv6 authenticated SQL session | pass | 12 | [pcap](dameng/dameng_ipv6.pcap) |
| dameng_length_boundary | S5: profile minimum non-empty payload boundary | pass | 12 | [pcap](dameng/dameng_length_boundary.pcap) |
| dameng_long_sql_mss | LG: 3000B SQL still one segment per event, session unbroken | pass | 12 | [pcap](dameng/dameng_long_sql_mss.pcap) |
| dameng_multi_flow_dynamic | MF: flows=3 dynamic src ports over single-connect baseline | pass | 24 | [pcap](dameng/dameng_multi_flow_dynamic.pcap) |
| dameng_multi_session | S8: two independent authenticated sessions | pass | 20 | [pcap](dameng/dameng_multi_session.pcap) |
| dameng_neg_auth_response_without_request | N: auth_response without prior auth_request | pass | 0 | [pcap]() |
| dameng_neg_close_not_last | N: close not last | pass | 0 | [pcap]() |
| dameng_neg_connect_not_first | N: first event not connect | pass | 0 | [pcap]() |
| dameng_neg_direction_mismatch | N: explicit direction inconsistent with kind | pass | 0 | [pcap]() |
| dameng_neg_empty_sql | N: sql_request without sql text | pass | 0 | [pcap]() |
| dameng_neg_events_sessions_exclusive | N: events and sessions coexist | pass | 0 | [pcap]() |
| dameng_neg_oversize | N6: message over implementation limit is rejected | pass | 0 | [pcap]() |
| dameng_neg_payload_size | N: unsupported payload_size | pass | 0 | [pcap]() |
| dameng_neg_port | N2: nonstandard destination port is rejected | pass | 0 | [pcap]() |
| dameng_neg_profile | N3: unknown wire profile is rejected | pass | 0 | [pcap]() |
| dameng_neg_session_empty_events | N: session with empty events | pass | 0 | [pcap]() |
| dameng_neg_sql_after_auth_error | N: sql after auth error | pass | 0 | [pcap]() |
| dameng_neg_sql_before_auth | N: sql before successful auth | pass | 0 | [pcap]() |
| dameng_neg_state | N4: SQL before authentication is rejected | pass | 0 | [pcap]() |
| dameng_neg_top_dameng_presence_reject | D-DAMENG-1 presence: layers + top-level dameng {} coexist = reject | pass | 0 | [pcap]() |
| dameng_neg_truncated | N5: truncated application message is rejected | pass | 0 | [pcap]() |
| dameng_neg_udp | N1: UDP carrier is rejected | pass | 0 | [pcap]() |
| dameng_neg_unknown_kind | N: unregistered event kind | pass | 0 | [pcap]() |
| dameng_neg_unknown_layer_field | N: dameng layer 6th key beyond 5-key whitelist | pass | 0 | [pcap]() |
| dameng_neg_wire_fault_unknown_kind | N: wire_fault unknown kind | pass | 0 | [pcap]() |
| dameng_neg_wire_fault_wrong_shape | N: wire_fault wrong shape | pass | 0 | [pcap]() |
| dameng_pcap_nic_consistency | NIC fixture pcap-side (port/direction consistency; port_group dual-path NIC run open) | pass | 12 | [pcap](dameng/dameng_pcap_nic_consistency.pcap) |
| dameng_sql_error | S4: SQL error response remains a distinct event | pass | 12 | [pcap](dameng/dameng_sql_error.pcap) |
| dameng_sql_success | S3: authenticated SELECT success | pass | 12 | [pcap](dameng/dameng_sql_success.pcap) |
