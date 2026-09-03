# stratum Pcap Test Results

Cases: 40 — pass 40, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| stratum_authorize | Authorize: subscribe + mining.authorize with success response | pass | 11 | [pcap](stratum/stratum_authorize.pcap) |
| stratum_authorize_reject | Authorize reject: mining.authorize with error[24] Unauthorized | pass | 11 | [pcap](stratum/stratum_authorize_reject.pcap) |
| stratum_client_get_version | Client.get_version: pool initiates reverse request, miner auto-responds | pass | 13 | [pcap](stratum/stratum_client_get_version.pcap) |
| stratum_client_show_message | Client.show_message: pool notification, id=null, no miner response | pass | 12 | [pcap](stratum/stratum_client_show_message.pcap) |
| stratum_concurrent_sessions | Concurrent sessions: three miners interleaved (A/B/C), concurrent=true | pass | 45 | [pcap](stratum/stratum_concurrent_sessions.pcap) |
| stratum_configure_version_rolling | BIP310 mining.configure: version-rolling + mask intersection, before subscribe | pass | 11 | [pcap](stratum/stratum_configure_version_rolling.pcap) |
| stratum_extranonce2_size8 | Extranonce2 size 8: subscribe declares size=8, submit 16hex en2 | pass | 15 | [pcap](stratum/stratum_extranonce2_size8.pcap) |
| stratum_extranonce_subscribe | Extranonce subscription: subscribe + mining.extranonce.subscribe | pass | 11 | [pcap](stratum/stratum_extranonce_subscribe.pcap) |
| stratum_id_correlation | ID correlation: arbitrary id sequence 100/101/102, paired by value | pass | 15 | [pcap](stratum/stratum_id_correlation.pcap) |
| stratum_ipv6 | IPv6: 2001:db8::75 → 2001:db8::100:75, IPv6 fixtures, offset 74 | pass | 9 | [pcap](stratum/stratum_ipv6.pcap) |
| stratum_line_packing | Line packing: set_difficulty+notify merged into 449B one segment (2 LF) | pass | 12 | [pcap](stratum/stratum_line_packing.pcap) |
| stratum_mining_lifecycle | Mining lifecycle: 11-line sequence, subscribe→authorize→2x(notify+submit) | pass | 18 | [pcap](stratum/stratum_mining_lifecycle.pcap) |
| stratum_mss_large_coinb1 | MSS large coinb1: coinb1 1444hex = 1717B, crosses MSS into 2 segments | pass | 16 | [pcap](stratum/stratum_mss_large_coinb1.pcap) |
| stratum_multi_session | Multi-session: two sequential sessions, session 2 packet 16, distinct en1 | pass | 30 | [pcap](stratum/stratum_multi_session.pcap) |
| stratum_neg_address_family | Negative: mixed address family (IPv6 on IPv4 chain), rejected | pass | 0 | [pcap]() |
| stratum_neg_carrier | Negative: carrier mismatch (missing tcp / UDP / port contradiction), rejected | pass | 0 | [pcap]() |
| stratum_neg_error_propagation | Negative: validator error swallowed / completed/0 packets, rejected | pass | 0 | [pcap]() |
| stratum_neg_framing | Negative: missing LF / CRLF / length prefix framing, rejected | pass | 0 | [pcap]() |
| stratum_neg_hex | Negative: invalid hex (odd length / 0x prefix / non-hex char), rejected | pass | 0 | [pcap]() |
| stratum_neg_id_correlation | Negative: id mismatch or pseudo-id or unfinished transaction id reuse, rejected | pass | 0 | [pcap]() |
| stratum_neg_job_correlation | Negative: submit job not from session or username mismatch, rejected | pass | 0 | [pcap]() |
| stratum_neg_json | Negative: invalid JSON (truncated/malformed), rejected at validator | pass | 0 | [pcap]() |
| stratum_neg_method | Negative: unknown method or direction violation, rejected | pass | 0 | [pcap]() |
| stratum_neg_params | Negative: wrong params count/types (e.g. subscribe empty array), rejected | pass | 0 | [pcap]() |
| stratum_neg_state | Negative: state machine violation (e.g. authorize before subscribe), rejected | pass | 0 | [pcap]() |
| stratum_notify_clean_jobs | Notify clean jobs: notify with clean_jobs=true variant | pass | 13 | [pcap](stratum/stratum_notify_clean_jobs.pcap) |
| stratum_notify_empty_merkle | Empty merkle: notify with merkle_branch=[], clean=true, 320B line | pass | 13 | [pcap](stratum/stratum_notify_empty_merkle.pcap) |
| stratum_notify_job | Notify job: set_difficulty + notify (clean=false, 9-element full line) | pass | 13 | [pcap](stratum/stratum_notify_job.pcap) |
| stratum_port_nondefault | Non-default port 4444: stratum lines identical to baseline (port not in wire) | pass | 9 | [pcap](stratum/stratum_port_nondefault.pcap) |
| stratum_prevhash_byteorder | Prevhash byte order: wire=byte-reversed(display), util.reverse_hash semantics | pass | 15 | [pcap](stratum/stratum_prevhash_byteorder.pcap) |
| stratum_reconnect_resubscribe | Reconnect resubscribe: session1 close, session2 reconnect with new en1 | pass | 30 | [pcap](stratum/stratum_reconnect_resubscribe.pcap) |
| stratum_rst_pool_kick | RST pool kick: normal mining flow then RST (tcp.flags.reset, no FIN) | pass | 12 | [pcap](stratum/stratum_rst_pool_kick.pcap) |
| stratum_set_difficulty | Set difficulty: 16384, minimum response line 36B carried here | pass | 12 | [pcap](stratum/stratum_set_difficulty.pcap) |
| stratum_set_difficulty_update | Difficulty update: 16384→32768, each difficulty applied to following job | pass | 15 | [pcap](stratum/stratum_set_difficulty_update.pcap) |
| stratum_set_extranonce | Extranonce rotation: set_extranonce(b3f10a44, 8) + submit 16hex en2 | pass | 17 | [pcap](stratum/stratum_set_extranonce.pcap) |
| stratum_set_version_mask | BIP310 set_version_mask: mask push 00003000, id=null, immediate effect | pass | 12 | [pcap](stratum/stratum_set_version_mask.pcap) |
| stratum_submit_accept | Submit accept: full mining flow, submit with result=true | pass | 15 | [pcap](stratum/stratum_submit_accept.pcap) |
| stratum_submit_reject | Submit reject: submit with result=false + error[21] Job not found | pass | 15 | [pcap](stratum/stratum_submit_reject.pcap) |
| stratum_submit_version_bits | Submit with version_bits: 6-param submit, 18000000 ⊆ 1fffe000 mask | pass | 17 | [pcap](stratum/stratum_submit_version_bits.pcap) |
| stratum_subscribe_ipv4 | IPv4 baseline: single subscribe request/response, IPv4 single-flow | pass | 9 | [pcap](stratum/stratum_subscribe_ipv4.pcap) |
