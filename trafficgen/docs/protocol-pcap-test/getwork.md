# getwork Pcap Test Results

Cases: 62 — pass 62, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| getwork_auth_basic_header | Authorization: Basic dXNlcjpwYXNz present (default form) | pass | 9 | [pcap](getwork/getwork_auth_basic_header.pcap) |
| getwork_body_mss_spanning | three apply transactions: requests coalesced 117B one segment, responses 1773B across MSS segments (tcp.stream reassembly) | pass | 10 | [pcap](getwork/getwork_body_mss_spanning.pcap) |
| getwork_concurrent_sessions | concurrent:true two sessions interleaved (tcp.stream distinct, per-session pairing intact) | pass | 18 | [pcap](getwork/getwork_concurrent_sessions.pcap) |
| getwork_cycle_repeat | mining cycle: getwork→submit→getwork→submit (ids 1-4, CL 39/591/297/35) | pass | 15 | [pcap](getwork/getwork_cycle_repeat.pcap) |
| getwork_dual_family | dual-session IPv6 (v4 leg is getwork_request_ipv4_8332), streams independent | pass | 18 | [pcap](getwork/getwork_dual_family.pcap) |
| getwork_empty_params_form | apply params exactly [] (frames hex tail "params":[]}) | pass | 9 | [pcap](getwork/getwork_empty_params_form.pcap) |
| getwork_error_null_success | success response error exactly null (result/error/id triple shape) | pass | 9 | [pcap](getwork/getwork_error_null_success.pcap) |
| getwork_host_header_value | Host header exact value 198.51.100.76:8332 | pass | 9 | [pcap](getwork/getwork_host_header_value.pcap) |
| getwork_http10_close | HTTP/1.0 observation form: no Host header, Connection: close, FIN after single transaction | pass | 9 | [pcap](getwork/getwork_http10_close.pcap) |
| getwork_http401_noauth | no-credentials request → 401 + WWW-Authenticate, empty body (observation form) | pass | 9 | [pcap](getwork/getwork_http401_noauth.pcap) |
| getwork_http500_rpc_error | HTTP 500 + RPC error object (code/message), request id preserved | pass | 9 | [pcap](getwork/getwork_http500_rpc_error.pcap) |
| getwork_id_large_value | boundary large numeric id 2147483647 (request body 48B) | pass | 9 | [pcap](getwork/getwork_id_large_value.pcap) |
| getwork_id_numeric_sequence | keep-alive three apply transactions, ids 1/2/3 incrementing and paired | pass | 13 | [pcap](getwork/getwork_id_numeric_sequence.pcap) |
| getwork_id_string_form | string id "rpc-001" form (request 47B, response echoes the same id) | pass | 9 | [pcap](getwork/getwork_id_string_form.pcap) |
| getwork_jsonpath_result_data | json.path=/result/data assertion channel (value = fixture data prefix) | pass | 9 | [pcap](getwork/getwork_jsonpath_result_data.pcap) |
| getwork_jsonrpc10_default | JSON-RPC 1.0 legacy form (request members id,method,params — no jsonrpc member) | pass | 9 | [pcap](getwork/getwork_jsonrpc10_default.pcap) |
| getwork_jsonrpc20_form | JSON-RPC 2.0 observation form (jsonrpc member prepended, request+response) | pass | 9 | [pcap](getwork/getwork_jsonrpc20_form.pcap) |
| getwork_keepalive_multi_transaction | keep-alive three transactions, Connection keep-alive throughout, CL-delimited | pass | 13 | [pcap](getwork/getwork_keepalive_multi_transaction.pcap) |
| getwork_keepalive_then_close | two keep-alive transactions then final response Connection: close + FIN | pass | 11 | [pcap](getwork/getwork_keepalive_then_close.pcap) |
| getwork_multi_body_single_segment | two transactions coalesced: requests 78B one segment, responses 626B one segment, CL-delimited split | pass | 9 | [pcap](getwork/getwork_multi_body_single_segment.pcap) |
| getwork_multi_session | two sessions sequential (session 2 handshake = packet 10), streams distinct, id sequences independent | pass | 18 | [pcap](getwork/getwork_multi_session.pcap) |
| getwork_neg_address_family | negative: address_family | pass | 0 | [pcap]() |
| getwork_neg_bad_json | negative: bad_json | pass | 0 | [pcap]() |
| getwork_neg_body_truncated | negative: body_truncated | pass | 0 | [pcap]() |
| getwork_neg_content_length_mismatch | negative: content_length_mismatch | pass | 0 | [pcap]() |
| getwork_neg_cross_session_work | negative: cross_session_work | pass | 0 | [pcap]() |
| getwork_neg_data_length | negative: data_length | pass | 0 | [pcap]() |
| getwork_neg_data_not_hex | negative: data_not_hex | pass | 0 | [pcap]() |
| getwork_neg_error_propagation | negative: error_propagation | pass | 0 | [pcap]() |
| getwork_neg_field_missing | negative: field_missing | pass | 0 | [pcap]() |
| getwork_neg_getwork_params_nonempty | negative: getwork_params_nonempty | pass | 0 | [pcap]() |
| getwork_neg_http_method_get | negative: http_method_get | pass | 0 | [pcap]() |
| getwork_neg_id_mismatch | negative: id_mismatch | pass | 0 | [pcap]() |
| getwork_neg_port_undeclared | negative: port_undeclared | pass | 0 | [pcap]() |
| getwork_neg_submit_two_params | negative: submit_two_params | pass | 0 | [pcap]() |
| getwork_neg_submit_work_uncorrelated | negative: submit_work_uncorrelated | pass | 0 | [pcap]() |
| getwork_neg_udp_carrier | negative: udp_carrier | pass | 0 | [pcap]() |
| getwork_neg_unknown_method | negative: unknown_method | pass | 0 | [pcap]() |
| getwork_new_work_distinct | two apply transactions return distinct work (second = fixture_work2 variant) | pass | 11 | [pcap](getwork/getwork_new_work_distinct.pcap) |
| getwork_no_frames_after_fin | single transaction + FINx2 teardown: exactly 9 packets, no tcp.len>0 after the last frame, no RST | pass | 9 | [pcap](getwork/getwork_no_frames_after_fin.pcap) |
| getwork_nonce_in_data | submit data: first 152 hex same as latest work, chars 153-160 = 2f9f2e1d (nonce field) | pass | 11 | [pcap](getwork/getwork_nonce_in_data.pcap) |
| getwork_pcap_nic_consistency | same three-transaction fixture drives both outputs (pcap asserted here; NIC capture orchestrated externally, same assertion set) | pass | 13 | [pcap](getwork/getwork_pcap_nic_consistency.pcap) |
| getwork_port80 | port 80 HTTP carrier (port is carrier, not identity) | pass | 9 | [pcap](getwork/getwork_port80.pcap) |
| getwork_port_nondefault_9332 | non-default port 9332 explicitly declared (no decode-as dependency) | pass | 9 | [pcap](getwork/getwork_port_nondefault_9332.pcap) |
| getwork_reconnect_new_stream | clean FIN close then new four-tuple (4078) with fresh work context (fixture_work2) | pass | 18 | [pcap](getwork/getwork_reconnect_new_stream.pcap) |
| getwork_request_ipv4_8332 | baseline apply transaction over IPv4/TCP/HTTP 8332 (id-paired) | pass | 9 | [pcap](getwork/getwork_request_ipv4_8332.pcap) |
| getwork_request_ipv6_8332 | IPv6 carrier (ipv6.nxt=6, HTTP start offset 74), address-family isolated | pass | 9 | [pcap](getwork/getwork_request_ipv6_8332.pcap) |
| getwork_retry_after_500 | same connection: 500 error then retry with new id, no FIN between | pass | 11 | [pcap](getwork/getwork_retry_after_500.pcap) |
| getwork_rst_interrupt | RST interrupt after the request (reset=1, no FIN teardown, no body frames after) | pass | 5 | [pcap](getwork/getwork_rst_interrupt.pcap) |
| getwork_session_state_isolation | two sessions each apply+submit; each submit correlates with its OWN session's work (nonce per stream) | pass | 22 | [pcap](getwork/getwork_session_state_isolation.pcap) |
| getwork_submit_accepted | getwork(data) submit → result:true (accepted) | pass | 11 | [pcap](getwork/getwork_submit_accepted.pcap) |
| getwork_submit_rejected_false | result:false is a legal rejection (positive form, not a planner error) | pass | 11 | [pcap](getwork/getwork_submit_rejected_false.pcap) |
| getwork_submit_result_object | object result third form {status,share_id} | pass | 11 | [pcap](getwork/getwork_submit_result_object.pcap) |
| getwork_submit_single_param | submit params exactly one element (G-2: no second param, method stays getwork) | pass | 11 | [pcap](getwork/getwork_submit_single_param.pcap) |
| getwork_target_boundary | boundary target fixture: first 12 hex 00000000ffff, tail 52 hex all zero | pass | 9 | [pcap](getwork/getwork_target_boundary.pcap) |
| getwork_uri_variant | explicit /rpc endpoint, Host unchanged | pass | 9 | [pcap](getwork/getwork_uri_variant.pcap) |
| getwork_work_data_length | work data exactly 256 hex (G-1: 128B) | pass | 9 | [pcap](getwork/getwork_work_data_length.pcap) |
| getwork_work_hash1_constant | work hash1 exactly 128 hex equal to the legacy constant (00000080+00*56+80020000) | pass | 9 | [pcap](getwork/getwork_work_hash1_constant.pcap) |
| getwork_work_hex_charset | four work fields all lowercase [0-9a-f] | pass | 9 | [pcap](getwork/getwork_work_hex_charset.pcap) |
| getwork_work_midstate_length | work midstate exactly 64 hex | pass | 9 | [pcap](getwork/getwork_work_midstate_length.pcap) |
| getwork_work_no_jobid | standard result exactly 4 members {data,target,midstate,hash1}, no job_id (G-2) | pass | 9 | [pcap](getwork/getwork_work_no_jobid.pcap) |
| getwork_work_target_length | work target exactly 64 hex | pass | 9 | [pcap](getwork/getwork_work_target_length.pcap) |
