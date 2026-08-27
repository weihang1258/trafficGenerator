# rtmfp Pcap Test Results

Cases: 24 — pass 24, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| rtmfp_binary_payload | RTMFP deterministic binary payload | pass | 3 | [pcap](rtmfp/rtmfp_binary_payload.pcap) |
| rtmfp_close | RTMFP close lifecycle | pass | 4 | [pcap](rtmfp/rtmfp_close.pcap) |
| rtmfp_fragment_reassembly | RTMFP three-fragment message reassembly | pass | 5 | [pcap](rtmfp/rtmfp_fragment_reassembly.pcap) |
| rtmfp_handshake_ipv4 | RTMFP IPv4 UDP handshake and session establishment | pass | 4 | [pcap](rtmfp/rtmfp_handshake_ipv4.pcap) |
| rtmfp_handshake_ipv6 | RTMFP IPv6 UDP handshake | pass | 3 | [pcap](rtmfp/rtmfp_handshake_ipv6.pcap) |
| rtmfp_ipv4_ipv6_same_payload | RTMFP same logical payload across address families | pass | 3 | [pcap](rtmfp/rtmfp_ipv4_ipv6_same_payload.pcap) |
| rtmfp_keepalive_bounded | RTMFP bounded keepalive and close | pass | 7 | [pcap](rtmfp/rtmfp_keepalive_bounded.pcap) |
| rtmfp_loss_and_ack_ranges | RTMFP loss fixture and ACK range | pass | 6 | [pcap](rtmfp/rtmfp_loss_and_ack_ranges.pcap) |
| rtmfp_low_latency_profile | RTMFP explicit low latency profile | pass | 3 | [pcap](rtmfp/rtmfp_low_latency_profile.pcap) |
| rtmfp_multi_flow | RTMFP multiple isolated flows | pass | 5 | [pcap](rtmfp/rtmfp_multi_flow.pcap) |
| rtmfp_multi_session | RTMFP isolated sessions on distinct ports | pass | 6 | [pcap](rtmfp/rtmfp_multi_session.pcap) |
| rtmfp_neg_ack_unknown | Reject ACK for unknown sequence | pass | 0 | [pcap]() |
| rtmfp_neg_cookie_session | Reject cookie and session mismatch | pass | 0 | [pcap]() |
| rtmfp_neg_fragment_gap | Reject missing RTMFP fragment | pass | 0 | [pcap]() |
| rtmfp_neg_length_overrun | Reject RTMFP message length overrun | pass | 0 | [pcap]() |
| rtmfp_neg_profile_carrier | Reject invalid RTMFP profile or carrier | pass | 0 | [pcap]() |
| rtmfp_neg_sequence_regress | Reject reliable sequence regression | pass | 0 | [pcap]() |
| rtmfp_neg_session_leak | Reject cross-session flow state reference | pass | 0 | [pcap]() |
| rtmfp_neg_short_header | Reject RTMFP short header | pass | 0 | [pcap]() |
| rtmfp_neg_state_order | Reject RTMFP state order violation | pass | 0 | [pcap]() |
| rtmfp_ping_pong | RTMFP explicit ping pong keepalive | pass | 4 | [pcap](rtmfp/rtmfp_ping_pong.pcap) |
| rtmfp_reliable_flow | RTMFP reliable flow with ACK | pass | 4 | [pcap](rtmfp/rtmfp_reliable_flow.pcap) |
| rtmfp_retransmission | RTMFP reliable retransmission keeps sequence | pass | 5 | [pcap](rtmfp/rtmfp_retransmission.pcap) |
| rtmfp_unreliable_flow | RTMFP unreliable flow without implicit retransmission | pass | 3 | [pcap](rtmfp/rtmfp_unreliable_flow.pcap) |
