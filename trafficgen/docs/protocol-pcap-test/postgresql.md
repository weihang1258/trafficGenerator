# postgresql Pcap Test Results

Cases: 86 — pass 86, fail 0, error 0

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
| postgresql_auth_cleartext | T-PG-12: AuthenticationCleartextPassword (subtype 3) + c2s PasswordMessage (opaque) | pass | 11 | [pcap](postgresql/postgresql_auth_cleartext.pcap) |
| postgresql_auth_failure_disconnect | A'-3.15②: authentication failure — server ErrorResponse then immediate close (no ReadyForQuery) | pass | 12 | [pcap](postgresql/postgresql_auth_failure_disconnect.pcap) |
| postgresql_auth_gss | T-PG-15: AuthenticationGSS (subtype 7) + c2s GSSResponse (opaque) | pass | 11 | [pcap](postgresql/postgresql_auth_gss.pcap) |
| postgresql_auth_gss_continue | T-PG-16: AuthenticationGSSContinue (subtype 8, Byte^n GSSAPI data) | pass | 11 | [pcap](postgresql/postgresql_auth_gss_continue.pcap) |
| postgresql_auth_kerberos_v5 | T-PG-11: AuthenticationKerberosV5 (subtype 2, no extra payload) | pass | 10 | [pcap](postgresql/postgresql_auth_kerberos_v5.pcap) |
| postgresql_auth_md5_salt | T-PG-13: AuthenticationMD5Password (subtype 5, 4-byte salt, length=12) + c2s digest | pass | 11 | [pcap](postgresql/postgresql_auth_md5_salt.pcap) |
| postgresql_auth_ok | T-PG-10: AuthenticationOk (subtype 0), length=8 | pass | 11 | [pcap](postgresql/postgresql_auth_ok.pcap) |
| postgresql_auth_sasl_continue | T-PG-19: AuthenticationSASLContinue (subtype 11) + c2s SASLResponse | pass | 11 | [pcap](postgresql/postgresql_auth_sasl_continue.pcap) |
| postgresql_auth_sasl_final | T-PG-20: AuthenticationSASLFinal (subtype 12) | pass | 11 | [pcap](postgresql/postgresql_auth_sasl_final.pcap) |
| postgresql_auth_sasl_mechanisms | T-PG-18: AuthenticationSASL (subtype 10): SCRAM-SHA-256 mechanism list + SASLInitialResponse | pass | 11 | [pcap](postgresql/postgresql_auth_sasl_mechanisms.pcap) |
| postgresql_auth_scm_credential | T-PG-14: AuthenticationSCMCredential (subtype 6, deprecated) | pass | 10 | [pcap](postgresql/postgresql_auth_scm_credential.pcap) |
| postgresql_auth_sspi | T-PG-17: AuthenticationSSPI (subtype 9) + c2s response | pass | 11 | [pcap](postgresql/postgresql_auth_sspi.pcap) |
| postgresql_backend_key_data | T-PG-23: BackendKeyData with explicit pid/secret | pass | 12 | [pcap](postgresql/postgresql_backend_key_data.pcap) |
| postgresql_cancel_request | T-PG-9: CancelRequest 16 bytes (magic + pid + secret) on an independent connection | pass | 8 | [pcap](postgresql/postgresql_cancel_request.pcap) |
| postgresql_data_row_null_and_multi | T-PG-31: multi-column DataRow including a NULL column (length -1) | pass | 14 | [pcap](postgresql/postgresql_data_row_null_and_multi.pcap) |
| postgresql_empty_query_response | T-PG-34: empty Simple Query ('Q' + NUL) answered by EmptyQueryResponse ('I') | pass | 14 | [pcap](postgresql/postgresql_empty_query_response.pcap) |
| postgresql_error_response_fields | T-PG-32: ErrorResponse field sequence (severity/code/message) terminated by a single 0x00 | pass | 14 | [pcap](postgresql/postgresql_error_response_fields.pcap) |
| postgresql_extended_close_flush | T-PG-38: extended Close→3 and Flush (no response); C byte is Close (c2s) vs Command completion (s2c) | pass | 16 | [pcap](postgresql/postgresql_extended_close_flush.pcap) |
| postgresql_extended_describe | T-PG-36: extended Describe — D(S)→t+T, D(P)→n (NoData) | pass | 17 | [pcap](postgresql/postgresql_extended_describe.pcap) |
| postgresql_extended_error_skip_to_sync | T-PG-39: extended-query error — server skips to Sync, then E+Z | pass | 15 | [pcap](postgresql/postgresql_extended_error_skip_to_sync.pcap) |
| postgresql_extended_execute_sync | T-PG-37: extended Execute(maxRows=1)→D/s and Sync→Z | pass | 18 | [pcap](postgresql/postgresql_extended_execute_sync.pcap) |
| postgresql_extended_parse_bind | T-PG-35: extended query P→1, B→2 (parameter format codes / values) | pass | 17 | [pcap](postgresql/postgresql_extended_parse_bind.pcap) |
| postgresql_function_call_response | T-PG-41: FunctionCall ('F') + FunctionCallResponse ('V') with a NULL result (-1) | pass | 14 | [pcap](postgresql/postgresql_function_call_response.pcap) |
| postgresql_gssenc_request | T-PG-8: GSSENCRequest 8-byte magic 04 D2 16 30 | pass | 8 | [pcap](postgresql/postgresql_gssenc_request.pcap) |
| postgresql_kingbase_dialect_port | T-PG-48: dialect=kingbase → contract port 54321 + mandatory decode_as | pass | 11 | [pcap](postgresql/postgresql_kingbase_dialect_port.pcap) |
| postgresql_multi_flow_dynamic | T-PG-46: flows=3 with per-flow ip/tcp dynamics (inc wrap / rand seed / list rotation) | pass | 33 | [pcap](postgresql/postgresql_multi_flow_dynamic.pcap) |
| postgresql_multi_query_rounds | A'-3.15①: same connection, three query rounds (long-lived session) | pass | 27 | [pcap](postgresql/postgresql_multi_query_rounds.pcap) |
| postgresql_multi_session_expansion | T-PG-45: sessions[] two independent connections (own src_port, own handshake/auth/query/teardown) | pass | 22 | [pcap](postgresql/postgresql_multi_session_expansion.pcap) |
| postgresql_neg_auth_data_not_hex | D-POSTGRESQL-1 负例：auth_data 非十六进制（设计 §3.4/§10 opaque 字节串） | pass | 0 | [pcap]() |
| postgresql_neg_auth_token_not_hex | D-POSTGRESQL-1 负例：auth_token 非十六进制（c2s opaque token 面） | pass | 0 | [pcap]() |
| postgresql_neg_empty_sql | T-PG-58: query with blank sql rejected | pass | 0 | [pcap]() |
| postgresql_neg_invalid_direction | T-PG-57: direction other than c2s/s2c rejected | pass | 0 | [pcap]() |
| postgresql_neg_noncontract_port | T-PG-50: explicit tcp.dst_port != contract port rejected (dialect=postgresql wants 5432) | pass | 0 | [pcap]() |
| postgresql_neg_password_before_ready | T-PG-55: c2s password before the server signaled ready (state machine) | pass | 0 | [pcap]() |
| postgresql_neg_presence_top_level_postgresql | T-PG-G6: layers + top-level postgresql sub-config presence rejected (G-PG-6 closed) | pass | 0 | [pcap]() |
| postgresql_neg_query_before_ready | T-PG-54: c2s query before the server signaled ready (state machine) | pass | 0 | [pcap]() |
| postgresql_neg_static_copy | T-PG-12.9: flows=2 with an all-static four-tuple rejected (static-copy gate) | pass | 0 | [pcap]() |
| postgresql_neg_terminate_then_query | T-PG-64: query after terminate rejected (closed-state guard, A′ wired) | pass | 0 | [pcap]() |
| postgresql_neg_udp_carrier | T-PG-49: UDP carrier rejected (postgresql is TCP-only) | pass | 0 | [pcap]() |
| postgresql_neg_unknown_dialect | T-PG-51: unregistered dialect value rejected | pass | 0 | [pcap]() |
| postgresql_neg_unknown_event_kind | T-PG-56: unregistered event kind rejected | pass | 0 | [pcap]() |
| postgresql_neg_unknown_layer_field | T-PG-59: sixth key inside the postgresql layer rejected by the V9 whitelist | pass | 0 | [pcap]() |
| postgresql_neg_unknown_wire_profile | T-PG-52: unregistered wire_profile rejected | pass | 0 | [pcap]() |
| postgresql_neg_wire_fault_message_limit | T-PG-61: wire_fault message_limit rejected (anchor: limit) | pass | 0 | [pcap]() |
| postgresql_neg_wire_fault_truncate_startup | T-PG-60: wire_fault truncate_startup rejected (anchor: length) | pass | 0 | [pcap]() |
| postgresql_neg_wire_fault_unknown_kind | T-PG-62: wire_fault with an unregistered kind rejected | pass | 0 | [pcap]() |
| postgresql_neg_wire_fault_wrong_shape | T-PG-63: wire_fault in a non-object shape (string) rejected | pass | 0 | [pcap]() |
| postgresql_neg_wire_profile_native_pending | T-PG-53: kingbase_native_pending registered but has no fixed payload | pass | 0 | [pcap]() |
| postgresql_negotiate_protocol_version | T-PG-42: NegotiateProtocolVersion ('v') — newest minor + unrecognized options (frames hex) | pass | 11 | [pcap](postgresql/postgresql_negotiate_protocol_version.pcap) |
| postgresql_notice_response | T-PG-33: NoticeResponse ('N') — same field layout as E, does not end the transaction | pass | 14 | [pcap](postgresql/postgresql_notice_response.pcap) |
| postgresql_notification_response | T-PG-40: NotificationResponse ('A') — pid + channel + payload (LISTEN async push) | pass | 14 | [pcap](postgresql/postgresql_notification_response.pcap) |
| postgresql_parameter_status_cycle | T-PG-21: 7 default ParameterStatus events cycled from the per-instance default table | pass | 14 | [pcap](postgresql/postgresql_parameter_status_cycle.pcap) |
| postgresql_parameter_status_explicit | T-PG-22: explicit ParameterStatus name/value pair | pass | 12 | [pcap](postgresql/postgresql_parameter_status_explicit.pcap) |
| postgresql_pcap_nic_consistency | T-PG-47: same fixture on both output paths (pcap + port_group/NIC) with identical field values | pass | 16 | [pcap](postgresql/postgresql_pcap_nic_consistency.pcap) |
| postgresql_query_command_tags | T-PG-29: CommandComplete tag family — INSERT 0 1 / UPDATE 3 / DELETE 2 / BEGIN | pass | 15 | [pcap](postgresql/postgresql_query_command_tags.pcap) |
| postgresql_query_long_sql_mss | T-PG-44: 3000-byte SQL crossing MSS — segmentation with the query reassembled | pass | 14 | [pcap](postgresql/postgresql_query_long_sql_mss.pcap) |
| postgresql_query_multi_statement | T-PG-28: multi-statement Simple Query (';') — no Z between statements, one Z at batch end | pass | 19 | [pcap](postgresql/postgresql_query_multi_statement.pcap) |
| postgresql_query_select_basic | T-PG-27: Simple Query 'SELECT 1' with the full T/D/C response family | pass | 16 | [pcap](postgresql/postgresql_query_select_basic.pcap) |
| postgresql_ready_failed_transaction | T-PG-26: ReadyForQuery status 'E' (failed transaction block) | pass | 12 | [pcap](postgresql/postgresql_ready_failed_transaction.pcap) |
| postgresql_ready_for_query_idle | T-PG-24: ReadyForQuery status 'I' (idle) | pass | 12 | [pcap](postgresql/postgresql_ready_for_query_idle.pcap) |
| postgresql_ready_in_transaction | T-PG-25: ReadyForQuery status 'T' (inside a transaction block) | pass | 12 | [pcap](postgresql/postgresql_ready_in_transaction.pcap) |
| postgresql_row_description_multi_column | T-PG-30: 3-column RowDescription (int16 count + per-column 7 fields) | pass | 15 | [pcap](postgresql/postgresql_row_description_multi_column.pcap) |
| postgresql_server_abort_rst | A'-3.15②: abnormal end — server RST instead of the FIN four-way teardown | pass | 8 | [pcap](postgresql/postgresql_server_abort_rst.pcap) |
| postgresql_ssl_request | T-PG-7: SSLRequest 8-byte magic 04 D2 16 2F (no response bytes) | pass | 8 | [pcap](postgresql/postgresql_ssl_request.pcap) |
| postgresql_startup_ipv4_basic | T-PG-1: IPv4 full session — handshake → Startup → R0 → S*7 → K → Z → Q → T/D/C → Z → X → teardown | pass | 23 | [pcap](postgresql/postgresql_startup_ipv4_basic.pcap) |
| postgresql_startup_ipv6_basic | T-PG-2: IPv6 same event sequence as T-PG-1 (ipv6.nxt=6, frame offset 74) | pass | 23 | [pcap](postgresql/postgresql_startup_ipv6_basic.pcap) |
| postgresql_startup_long_params_mss | T-PG-43: Startup parameters longer than the default MSS 1460 — TCP-layer segmentation | pass | 9 | [pcap](postgresql/postgresql_startup_long_params_mss.pcap) |
| postgresql_startup_params_empty | T-PG-3: empty-parameter StartupMessage (minimum legal shape, length=9) | pass | 8 | [pcap](postgresql/postgresql_startup_params_empty.pcap) |
| postgresql_startup_params_multi | T-PG-4: StartupMessage with user+database (length=35, params key-sorted) | pass | 8 | [pcap](postgresql/postgresql_startup_params_multi.pcap) |
| postgresql_startup_protocol_v3_1 | T-PG-5: protocol version 0x00030001 (frames hex; dissector reads Unknown) | pass | 8 | [pcap](postgresql/postgresql_startup_protocol_v3_1.pcap) |
| postgresql_startup_protocol_v3_2 | T-PG-6: protocol version 0x00030002 (PostgreSQL 18, frames hex) | pass | 8 | [pcap](postgresql/postgresql_startup_protocol_v3_2.pcap) |
