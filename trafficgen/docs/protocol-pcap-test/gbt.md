# gbt Pcap Test Results

Cases: 81 — pass 81, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| gbt_auth_basic_header | Authorization: Basic header present | pass | 9 | [pcap](gbt/gbt_auth_basic_header.pcap) |
| gbt_bits_8hex | bits exactly 8 hex | pass | 9 | [pcap](gbt/gbt_bits_8hex.pcap) |
| gbt_body_mss_spanning | 3 responses coalesced 1752B spanning 2 segments | pass | 10 | [pcap](gbt/gbt_body_mss_spanning.pcap) |
| gbt_capabilities_response | Template capabilities=[proposal] | pass | 9 | [pcap](gbt/gbt_capabilities_response.pcap) |
| gbt_coinbaseaux_flags | coinbaseaux.flags=706f6f6c31 | pass | 9 | [pcap](gbt/gbt_coinbaseaux_flags.pcap) |
| gbt_coinbasevalue_bigint | coinbasevalue=5000000000 big integer exact | pass | 9 | [pcap](gbt/gbt_coinbasevalue_bigint.pcap) |
| gbt_concurrent_sessions | concurrent sessions interleaved (tcp.stream distinct) | pass | 18 | [pcap](gbt/gbt_concurrent_sessions.pcap) |
| gbt_dual_family | dual family: v6 dual-session (v4 member is gbt_template_ipv4_8332) | pass | 18 | [pcap](gbt/gbt_dual_family.pcap) |
| gbt_empty_params_form | Baseline params exactly [] | pass | 9 | [pcap](gbt/gbt_empty_params_form.pcap) |
| gbt_height_value | height=1000 exact | pass | 9 | [pcap](gbt/gbt_height_value.pcap) |
| gbt_host_header_value | Host header exact value | pass | 9 | [pcap](gbt/gbt_host_header_value.pcap) |
| gbt_http10_close | HTTP/1.0 + close, single transaction | pass | 9 | [pcap](gbt/gbt_http10_close.pcap) |
| gbt_http401_noauth | No credentials: 401 + WWW-Authenticate, empty body | pass | 9 | [pcap](gbt/gbt_http401_noauth.pcap) |
| gbt_http500_rpc_error | HTTP 500 + error object (code/message, id preserved) | pass | 9 | [pcap](gbt/gbt_http500_rpc_error.pcap) |
| gbt_id_large_value | Large numeric id 2147483647 | pass | 9 | [pcap](gbt/gbt_id_large_value.pcap) |
| gbt_id_numeric_sequence | keep-alive 3 transactions with ids 1/2/3 | pass | 13 | [pcap](gbt/gbt_id_numeric_sequence.pcap) |
| gbt_id_string_form | String id form | pass | 9 | [pcap](gbt/gbt_id_string_form.pcap) |
| gbt_jsonrpc10_default | bitcoin-cli JSON-RPC form: request jsonrpc:1.0, response without | pass | 9 | [pcap](gbt/gbt_jsonrpc10_default.pcap) |
| gbt_jsonrpc20_form | JSON-RPC 2.0 observed form | pass | 9 | [pcap](gbt/gbt_jsonrpc20_form.pcap) |
| gbt_keepalive_multi_transaction | keep-alive 3 transactions, no intermediate FIN | pass | 13 | [pcap](gbt/gbt_keepalive_multi_transaction.pcap) |
| gbt_keepalive_then_close | keep-alive then close, FIN after | pass | 11 | [pcap](gbt/gbt_keepalive_then_close.pcap) |
| gbt_limits_values | sigoplimit=80000 / sizelimit=4000000 scalars | pass | 9 | [pcap](gbt/gbt_limits_values.pcap) |
| gbt_longpoll_request | longpoll: POST /longpoll + new template on return | pass | 11 | [pcap](gbt/gbt_longpoll_request.pcap) |
| gbt_longpoll_uri_field | longpolluri field present (BIP 22) | pass | 9 | [pcap](gbt/gbt_longpoll_uri_field.pcap) |
| gbt_longpollid_parameter | longpollid parameter form | pass | 11 | [pcap](gbt/gbt_longpollid_parameter.pcap) |
| gbt_mintime_curtime | mintime/curtime exact values | pass | 9 | [pcap](gbt/gbt_mintime_curtime.pcap) |
| gbt_multi_body_single_segment | two transactions coalesced into single segments each direction | pass | 9 | [pcap](gbt/gbt_multi_body_single_segment.pcap) |
| gbt_multi_session | two sessions sequential (second handshake at packet 10) | pass | 18 | [pcap](gbt/gbt_multi_session.pcap) |
| gbt_mutable_values | mutable definition values + string rollup | pass | 9 | [pcap](gbt/gbt_mutable_values.pcap) |
| gbt_neg_address_family | address family mismatch | pass | 0 | [pcap]() |
| gbt_neg_bad_json | body is not valid JSON | pass | 0 | [pcap]() |
| gbt_neg_bip9_field | vbavailable/vbrequired BIP 9 boundary | pass | 0 | [pcap]() |
| gbt_neg_bits_length | bits wrong length | pass | 0 | [pcap]() |
| gbt_neg_body_truncated | body truncated (CL exceeds actual) | pass | 0 | [pcap]() |
| gbt_neg_coinbasetxn_form | coinbasetxn full form boundary | pass | 0 | [pcap]() |
| gbt_neg_content_length_mismatch | Content-Length mismatch | pass | 0 | [pcap]() |
| gbt_neg_error_propagation | error propagation: task error not fake success | pass | 0 | [pcap]() |
| gbt_neg_field_missing | template missing height | pass | 0 | [pcap]() |
| gbt_neg_height_nonincrement | refresh height not +1 | pass | 0 | [pcap]() |
| gbt_neg_http_method_get | GET method carrier | pass | 0 | [pcap]() |
| gbt_neg_id_mismatch | response id mismatch | pass | 0 | [pcap]() |
| gbt_neg_line_profile | jsonrpc-line fabricated profile | pass | 0 | [pcap]() |
| gbt_neg_longpollid_missing | longpoll missing longpollid | pass | 0 | [pcap]() |
| gbt_neg_longpollid_stale | longpollid stale | pass | 0 | [pcap]() |
| gbt_neg_mode_invalid | mode value out of range | pass | 0 | [pcap]() |
| gbt_neg_noncerange_length | noncerange wrong length | pass | 0 | [pcap]() |
| gbt_neg_port_undeclared | port not declared | pass | 0 | [pcap]() |
| gbt_neg_prevhash_length | prevhash wrong length | pass | 0 | [pcap]() |
| gbt_neg_submitblock_no_hexdata | submitblock missing hexdata | pass | 0 | [pcap]() |
| gbt_neg_submitblock_third_param | submitblock three params | pass | 0 | [pcap]() |
| gbt_neg_target_length | target wrong length | pass | 0 | [pcap]() |
| gbt_neg_template_params_nonobject | getblocktemplate params[0] non-object | pass | 0 | [pcap]() |
| gbt_neg_udp_carrier | UDP carrier rejected | pass | 0 | [pcap]() |
| gbt_neg_unknown_method | unknown method (getwork is separate family) | pass | 0 | [pcap]() |
| gbt_neg_unknown_rule | unknown rule (taproot) | pass | 0 | [pcap]() |
| gbt_neg_witness_commitment | default_witness_commitment BIP 145 boundary | pass | 0 | [pcap]() |
| gbt_neg_workid_mismatch | workid mismatch | pass | 0 | [pcap]() |
| gbt_no_frames_after_fin | single transaction + FIN, no frames after, no RST | pass | 9 | [pcap](gbt/gbt_no_frames_after_fin.pcap) |
| gbt_noncerange_16hex | noncerange exactly 16 hex | pass | 9 | [pcap](gbt/gbt_noncerange_16hex.pcap) |
| gbt_port_nondefault_18332 | Non-default port 18332 explicit (no DecodeAs needed) | pass | 9 | [pcap](gbt/gbt_port_nondefault_18332.pcap) |
| gbt_prevhash_64hex | previousblockhash exactly 64 hex | pass | 9 | [pcap](gbt/gbt_prevhash_64hex.pcap) |
| gbt_proposal_mode | proposal mode: result true (BIP 23) | pass | 11 | [pcap](gbt/gbt_proposal_mode.pcap) |
| gbt_proposal_reject | proposal reject reason observed | pass | 11 | [pcap](gbt/gbt_proposal_reject.pcap) |
| gbt_reconnect_new_stream | reconnect: new 4-tuple after clean close | pass | 18 | [pcap](gbt/gbt_reconnect_new_stream.pcap) |
| gbt_retry_after_500 | retry after 500 (new id, same connection) | pass | 11 | [pcap](gbt/gbt_retry_after_500.pcap) |
| gbt_rst_interrupt | RST interrupt: no response body, no FIN | pass | 5 | [pcap](gbt/gbt_rst_interrupt.pcap) |
| gbt_rules_request | rules=segwit request form | pass | 9 | [pcap](gbt/gbt_rules_request.pcap) |
| gbt_session_state_isolation | session state isolation: workid/id per-flow | pass | 22 | [pcap](gbt/gbt_session_state_isolation.pcap) |
| gbt_submitblock_accepted | submitblock accepted result:null | pass | 11 | [pcap](gbt/gbt_submitblock_accepted.pcap) |
| gbt_submitblock_error_500 | submitblock error: 500 + error object | pass | 9 | [pcap](gbt/gbt_submitblock_error_500.pcap) |
| gbt_submitblock_rejected_reason | submitblock rejected: result string reason | pass | 11 | [pcap](gbt/gbt_submitblock_rejected_reason.pcap) |
| gbt_submitblock_with_workid | submitblock [hexdata, workid] double-param | pass | 11 | [pcap](gbt/gbt_submitblock_with_workid.pcap) |
| gbt_target_64hex | target exactly 64 hex | pass | 9 | [pcap](gbt/gbt_target_64hex.pcap) |
| gbt_template_ipv4_8332 | IPv4/TCP/HTTP 8332 baseline: getblocktemplate + 18-key template | pass | 9 | [pcap](gbt/gbt_template_ipv4_8332.pcap) |
| gbt_template_ipv6_8332 | IPv6 fixture: template transaction | pass | 9 | [pcap](gbt/gbt_template_ipv6_8332.pcap) |
| gbt_template_keyset | Template 18-key order assertion | pass | 9 | [pcap](gbt/gbt_template_keyset.pcap) |
| gbt_template_large_mss | big template 5512B body spanning 4 segments | pass | 12 | [pcap](gbt/gbt_template_large_mss.pcap) |
| gbt_template_refresh | template refresh: height+1/curtime+600 distinct | pass | 11 | [pcap](gbt/gbt_template_refresh.pcap) |
| gbt_transactions_elements | 1 tx element 6 keys (tx1 template 884B) | pass | 9 | [pcap](gbt/gbt_transactions_elements.pcap) |
| gbt_transactions_empty | transactions empty array form (plain template) | pass | 9 | [pcap](gbt/gbt_transactions_empty.pcap) |
| gbt_workid_template | template workid=w-1 present | pass | 9 | [pcap](gbt/gbt_workid_template.pcap) |
