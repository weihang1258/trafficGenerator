# bgp Pcap Test Results

Cases: 43 — pass 43, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| bgp_a_community_no_advertise | A': COMMUNITIES NO_ADVERTISE | pass | 12 | [pcap](bgp/bgp_a_community_no_advertise.pcap) |
| bgp_a_default_events_nil | A': events key absent -> default 6-event stream | pass | 13 | [pcap](bgp/bgp_a_default_events_nil.pcap) |
| bgp_a_multi_flow_dynamic | A': flows=3 with ip.src inc + ip.dst rand(seed) + tcp.src_port inc | pass | 33 | [pcap](bgp/bgp_a_multi_flow_dynamic.pcap) |
| bgp_a_multi_update_rounds | A': same connection 3 UPDATE rounds, distinct NLRI | pass | 14 | [pcap](bgp/bgp_a_multi_update_rounds.pcap) |
| bgp_a_neg_bad_identifier | A' neg: bad identifier | pass | 0 | [pcap]() |
| bgp_a_neg_bad_nexthop | A' neg: bad next_hop | pass | 0 | [pcap]() |
| bgp_a_neg_hold_time_small | A' neg: hold_time=2 (RFC 4271 §4.2 allows 0 or >=3) | pass | 0 | [pcap]() |
| bgp_a_neg_keepalive_before_open | A' neg: KA before OPEN | pass | 0 | [pcap]() |
| bgp_a_neg_msg_overflow_4096 | A' neg: UPDATE exceeds 4096 | pass | 0 | [pcap]() |
| bgp_a_neg_notification_before_open | A' neg: NOTIF before OPEN | pass | 0 | [pcap]() |
| bgp_a_neg_notification_not_last | A' neg: NOTIF not last | pass | 0 | [pcap]() |
| bgp_a_neg_notification_other_code | A' neg: NOTIF Cease(6) | pass | 0 | [pcap]() |
| bgp_a_neg_open_after_established | A' neg: OPEN after application events | pass | 0 | [pcap]() |
| bgp_a_neg_single_open | A' neg: single OPEN | pass | 0 | [pcap]() |
| bgp_a_notification_multi_session | A': two sessions, s0 NOTIF-terminated, s1 keepalive | pass | 21 | [pcap](bgp/bgp_a_notification_multi_session.pcap) |
| bgp_a_origin_egp | A': ORIGIN=1 | pass | 12 | [pcap](bgp/bgp_a_origin_egp.pcap) |
| bgp_a_origin_incomplete | A': ORIGIN=2 | pass | 12 | [pcap](bgp/bgp_a_origin_incomplete.pcap) |
| bgp_a_server_abort_rst | A': server RST abort (tcp layer rst capability) | pass | 8 | [pcap](bgp/bgp_a_server_abort_rst.pcap) |
| bgp_a_update_combined_withdraw_nlri | A': single UPDATE with withdrawn + attrs + NLRI | pass | 12 | [pcap](bgp/bgp_a_update_combined_withdraw_nlri.pcap) |
| bgp_a_update_multi_session | A': two sessions, s0 full-attribute UPDATE, s1 keepalive-only | pass | 23 | [pcap](bgp/bgp_a_update_multi_session.pcap) |
| bgp_connect | S1: TCP/179 connect without BGP application events | pass | 7 | [pcap](bgp/bgp_connect.pcap) |
| bgp_hold_time_zero | S6: OPEN hold time zero is observable and valid | pass | 11 | [pcap](bgp/bgp_hold_time_zero.pcap) |
| bgp_ipv4_nlri_32 | S7: IPv4 /32 NLRI prefix byte boundary | pass | 12 | [pcap](bgp/bgp_ipv4_nlri_32.pcap) |
| bgp_ipv6_transport | S8: IPv6 TCP transport with RFC 4271 IPv4 BGP identifier | pass | 11 | [pcap](bgp/bgp_ipv6_transport.pcap) |
| bgp_keepalive_length_boundary | S10: minimum legal BGP length 19 KEEPALIVE | pass | 11 | [pcap](bgp/bgp_keepalive_length_boundary.pcap) |
| bgp_multi_session | S9: two independent BGP sessions | pass | 22 | [pcap](bgp/bgp_multi_session.pcap) |
| bgp_neg_address | N9: IPv6 NLRI in IPv4 profile rejected | pass | 0 | [pcap]() |
| bgp_neg_as | N7: My AS outside two-octet range rejected | pass | 0 | [pcap]() |
| bgp_neg_flat_count | P2判死: top-level flat count alongside layers | pass | 0 | [pcap]() |
| bgp_neg_length | N4: invalid message length rejected | pass | 0 | [pcap]() |
| bgp_neg_marker | N3: non-all-ones marker rejected | pass | 0 | [pcap]() |
| bgp_neg_mp_reach_profile | N2: unimplemented MP_REACH IPv6 profile rejected | pass | 0 | [pcap]() |
| bgp_neg_presence_top_level_bgp | P2判死: layers + top-level bgp sub-config coexist | pass | 0 | [pcap]() |
| bgp_neg_state | N8: UPDATE before OPEN exchange rejected | pass | 0 | [pcap]() |
| bgp_neg_static_copy_multiflow | P2判死: static four-tuple with flows>1 (12.9) | pass | 0 | [pcap]() |
| bgp_neg_stray_src_mac | P2判死: top-level src_mac alongside layers (M5②) | pass | 0 | [pcap]() |
| bgp_neg_type | N5: unknown BGP message type rejected | pass | 0 | [pcap]() |
| bgp_neg_udp | N1: UDP carrier rejected | pass | 0 | [pcap]() |
| bgp_neg_version | N6: OPEN version other than 4 rejected | pass | 0 | [pcap]() |
| bgp_notification_hold_expired | S5: NOTIFICATION Hold Timer Expired then TCP termination | pass | 10 | [pcap](bgp/bgp_notification_hold_expired.pcap) |
| bgp_open_keepalive | S2: OPEN exchange then bidirectional KEEPALIVE | pass | 11 | [pcap](bgp/bgp_open_keepalive.pcap) |
| bgp_update_attributes | S3: IPv4 UPDATE with ORIGIN AS_PATH NEXT_HOP MED LOCAL_PREF COMMUNITIES | pass | 12 | [pcap](bgp/bgp_update_attributes.pcap) |
| bgp_update_withdraw | S4: UPDATE withdrawing an IPv4 /24 route | pass | 12 | [pcap](bgp/bgp_update_withdraw.pcap) |
