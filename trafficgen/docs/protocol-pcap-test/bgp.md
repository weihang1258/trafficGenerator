# bgp Pcap Test Results

Cases: 19 — pass 19, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| bgp_connect | S1: TCP/179 connect without BGP application events | pass | 7 | [pcap](bgp/bgp_connect.pcap) |
| bgp_hold_time_zero | S6: OPEN hold time zero is observable and valid | pass | 11 | [pcap](bgp/bgp_hold_time_zero.pcap) |
| bgp_ipv4_nlri_32 | S7: IPv4 /32 NLRI prefix byte boundary | pass | 12 | [pcap](bgp/bgp_ipv4_nlri_32.pcap) |
| bgp_ipv6_transport | S8: IPv6 TCP transport with RFC 4271 IPv4 BGP identifier | pass | 11 | [pcap](bgp/bgp_ipv6_transport.pcap) |
| bgp_keepalive_length_boundary | S10: minimum legal BGP length 19 KEEPALIVE | pass | 11 | [pcap](bgp/bgp_keepalive_length_boundary.pcap) |
| bgp_multi_session | S9: two independent BGP sessions | pass | 22 | [pcap](bgp/bgp_multi_session.pcap) |
| bgp_neg_address | N9: IPv6 NLRI in IPv4 profile rejected | pass | 0 | [pcap]() |
| bgp_neg_as | N7: My AS outside two-octet range rejected | pass | 0 | [pcap]() |
| bgp_neg_length | N4: invalid message length rejected | pass | 0 | [pcap]() |
| bgp_neg_marker | N3: non-all-ones marker rejected | pass | 0 | [pcap]() |
| bgp_neg_mp_reach_profile | N2: unimplemented MP_REACH IPv6 profile rejected | pass | 0 | [pcap]() |
| bgp_neg_state | N8: UPDATE before OPEN exchange rejected | pass | 0 | [pcap]() |
| bgp_neg_type | N5: unknown BGP message type rejected | pass | 0 | [pcap]() |
| bgp_neg_udp | N1: UDP carrier rejected | pass | 0 | [pcap]() |
| bgp_neg_version | N6: OPEN version other than 4 rejected | pass | 0 | [pcap]() |
| bgp_notification_hold_expired | S5: NOTIFICATION Hold Timer Expired then TCP termination | pass | 10 | [pcap](bgp/bgp_notification_hold_expired.pcap) |
| bgp_open_keepalive | S2: OPEN exchange then bidirectional KEEPALIVE | pass | 11 | [pcap](bgp/bgp_open_keepalive.pcap) |
| bgp_update_attributes | S3: IPv4 UPDATE with ORIGIN AS_PATH NEXT_HOP MED LOCAL_PREF COMMUNITIES | pass | 12 | [pcap](bgp/bgp_update_attributes.pcap) |
| bgp_update_withdraw | S4: UPDATE withdrawing an IPv4 /24 route | pass | 12 | [pcap](bgp/bgp_update_withdraw.pcap) |
