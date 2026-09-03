# ethmining Pcap Test Results

Cases: 32 — pass 32, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| ethmining_authorize | Authorize success: subscribe + mining.authorize (result=true) | pass | 11 | [pcap](ethmining/ethmining_authorize.pcap) |
| ethmining_authorize_reject | Authorize reject: mining.authorize with error[24] Unauthorized user | pass | 11 | [pcap](ethmining/ethmining_authorize_reject.pcap) |
| ethmining_custom_port | Non-default port 3353: ethmining lines identical to baseline, port not in wire | pass | 9 | [pcap](ethmining/ethmining_custom_port.pcap) |
| ethmining_extranonce_max3 | Extranonce 3B max: subscribe a2eea0 + submit 5B minernonce (8B total nonce) | pass | 15 | [pcap](ethmining/ethmining_extranonce_max3.pcap) |
| ethmining_extranonce_subscribe | Extranonce subscribe: subscribe + mining.extranonce.subscribe (true) | pass | 11 | [pcap](ethmining/ethmining_extranonce_subscribe.pcap) |
| ethmining_hex_prefix | Hex prefix 0x dialect: session-wide 0x prefix on extranonce/job/seed/header/nonce | pass | 15 | [pcap](ethmining/ethmining_hex_prefix.pcap) |
| ethmining_id_correlation | ID correlation: arbitrary id sequence 100/101/102, paired by value | pass | 15 | [pcap](ethmining/ethmining_id_correlation.pcap) |
| ethmining_ipv6 | IPv6: 2001:db8::73 -> 2001:db8::100:73, IPv6 fixtures | pass | 9 | [pcap](ethmining/ethmining_ipv6.pcap) |
| ethmining_line_packing | Line packing: set_difficulty+notify merged into 259B one segment (2 LF) | pass | 12 | [pcap](ethmining/ethmining_line_packing.pcap) |
| ethmining_long_username | Long username 68 chars: authorize + submit reuse same long username | pass | 15 | [pcap](ethmining/ethmining_long_username.pcap) |
| ethmining_mining_lifecycle | Mining lifecycle: subscribe->authorize->diff->notify+submit(A)->notify+submit(B) on one TCP stream | pass | 18 | [pcap](ethmining/ethmining_mining_lifecycle.pcap) |
| ethmining_mss_large_jobid | MSS large job_id: 1500 hex chars (1691B notify crosses MSS 1460 into 2 segments) | pass | 14 | [pcap](ethmining/ethmining_mss_large_jobid.pcap) |
| ethmining_multi_session | Multi-session: two miners on distinct src_ports, distinct en/username/job | pass | 30 | [pcap](ethmining/ethmining_multi_session.pcap) |
| ethmining_neg_carrier | Negative: carrier mismatch (missing tcp / UDP / port mismatch), rejected | pass | 0 | [pcap]() |
| ethmining_neg_error_propagation | Negative: validator error swallowed / completed/0 packets, rejected | pass | 0 | [pcap]() |
| ethmining_neg_framing | Negative: missing LF / CRLF / length prefix framing, rejected | pass | 0 | [pcap]() |
| ethmining_neg_hex | Negative: invalid hex (odd length / 0x prefix mixing / extranonce>3B / complement mismatch / non-hex char), rejected | pass | 0 | [pcap]() |
| ethmining_neg_id_correlation | Negative: id mismatch or pseudo id or intra-session id reuse, rejected | pass | 0 | [pcap]() |
| ethmining_neg_job_correlation | Negative: submit job not from session or worker mismatch, rejected | pass | 0 | [pcap]() |
| ethmining_neg_json | Negative: invalid JSON (truncated/malformed), rejected at validator | pass | 0 | [pcap]() |
| ethmining_neg_method | Negative: unknown method or direction violation, rejected | pass | 0 | [pcap]() |
| ethmining_neg_params | Negative: wrong params count/types (subscribe 1-elem, clean_jobs non-bool, set_ext 2-elem), rejected | pass | 0 | [pcap]() |
| ethmining_neg_state | Negative: state machine violation (submit before subscribe, close then submit), rejected | pass | 0 | [pcap]() |
| ethmining_notify_clean_jobs | Notify clean_jobs=true variant | pass | 13 | [pcap](ethmining/ethmining_notify_clean_jobs.pcap) |
| ethmining_notify_job | Notify job: set_difficulty + notify clean=false (4-element full line) | pass | 13 | [pcap](ethmining/ethmining_notify_job.pcap) |
| ethmining_set_difficulty | Set difficulty 0.5 (minimum response line 36B via authorize, 60B notify) | pass | 13 | [pcap](ethmining/ethmining_set_difficulty.pcap) |
| ethmining_set_difficulty_default | Default difficulty: no set_difficulty before first notify (1.0 fallback) | pass | 12 | [pcap](ethmining/ethmining_set_difficulty_default.pcap) |
| ethmining_set_difficulty_update | Difficulty update: 0.5 then 5000012.0, each diff applies to following job | pass | 15 | [pcap](ethmining/ethmining_set_difficulty_update.pcap) |
| ethmining_set_extranonce | Extranonce rotation: extranonce.subscribe + set_extranonce(a2eea0,3B) + submit 5B nonce (complement 8B) | pass | 18 | [pcap](ethmining/ethmining_set_extranonce.pcap) |
| ethmining_submit_accept | Submit accept: full mining flow, submit with result=true | pass | 15 | [pcap](ethmining/ethmining_submit_accept.pcap) |
| ethmining_submit_reject | Submit reject: submit with result=false + error[-1] Job not found | pass | 15 | [pcap](ethmining/ethmining_submit_reject.pcap) |
| ethmining_subscribe_ipv4 | IPv4 baseline: subscribe request/response | pass | 9 | [pcap](ethmining/ethmining_subscribe_ipv4.pcap) |
