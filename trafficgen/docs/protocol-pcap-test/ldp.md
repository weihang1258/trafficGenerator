# ldp Pcap Test Results

Cases: 25 — pass 23, fail 0, error 2

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| ldp_address_ipv4 | S3: IPv4 Address message after session initialization | pass | 10 | [pcap](ldp/ldp_address_ipv4.pcap) |
| ldp_dual_adjacency | S14: basic and targeted discovery adjacencies plus TCP session | error | 0 | `` |
| ldp_label_mapping_host32 | S8: IPv4 /32 host-route Label Mapping | pass | 10 | [pcap](ldp/ldp_label_mapping_host32.pcap) |
| ldp_label_mapping_ipv4 | S4: IPv4 /24 Label Mapping with Generic Label | pass | 10 | [pcap](ldp/ldp_label_mapping_ipv4.pcap) |
| ldp_label_release_ipv4 | S7: IPv4 /24 Label Release after Mapping | pass | 11 | [pcap](ldp/ldp_label_release_ipv4.pcap) |
| ldp_label_request_ipv4 | S5: IPv4 /24 Label Request | pass | 10 | [pcap](ldp/ldp_label_request_ipv4.pcap) |
| ldp_label_withdraw_ipv4 | S6: IPv4 /24 Label Withdraw after Mapping | pass | 11 | [pcap](ldp/ldp_label_withdraw_ipv4.pcap) |
| ldp_neg_carrier | N1: LDP without UDP or TCP carrier | pass | 0 | [pcap]() |
| ldp_neg_checksum | N11: invalid transport checksum rejected | pass | 0 | [pcap]() |
| ldp_neg_ipv6_profile | N3: IPv6 transport/profile is not silently mixed into IPv4 | pass | 0 | [pcap]() |
| ldp_neg_label_bounds | N8: Generic Label exceeds 20-bit bound | pass | 0 | [pcap]() |
| ldp_neg_message_length | N5: declared message length mismatch | pass | 0 | [pcap]() |
| ldp_neg_pdu_length | N4: declared PDU length mismatch | pass | 0 | [pcap]() |
| ldp_neg_port | N2: discovery with non-646 UDP port | pass | 0 | [pcap]() |
| ldp_neg_prefix_bounds | N9: IPv4 FEC prefix length exceeds 32 | pass | 0 | [pcap]() |
| ldp_neg_state | N10: KeepAlive before Initialization | pass | 0 | [pcap]() |
| ldp_neg_tlv_length | N6: declared TLV length mismatch | pass | 0 | [pcap]() |
| ldp_neg_unknown_message | N7: unknown LDP message type | pass | 0 | [pcap]() |
| ldp_notification_shutdown | S11: Notification status event terminates the LDP session | pass | 10 | [pcap](ldp/ldp_notification_shutdown.pcap) |
| ldp_ordered_dod_allocation | S12: downstream-on-demand ordered label request/mapping | pass | 11 | [pcap](ldp/ldp_ordered_dod_allocation.pcap) |
| ldp_tcp_initialization | S1: TCP/646 session Initialization in both directions | pass | 9 | [pcap](ldp/ldp_tcp_initialization.pcap) |
| ldp_tcp_keepalive | S2: Initialization followed by bidirectional KeepAlive | pass | 11 | [pcap](ldp/ldp_tcp_keepalive.pcap) |
| ldp_tcp_multi_session | S13: two independent parallel TCP/646 LDP sessions | error | 0 | `` |
| ldp_udp_parallel_hellos | S10: basic discovery Hellos in both directions | pass | 2 | [pcap](ldp/ldp_udp_parallel_hellos.pcap) |
| ldp_udp_targeted_hello | S9: targeted UDP/646 Hello with transport address | pass | 1 | [pcap](ldp/ldp_udp_targeted_hello.pcap) |

## Failures

### ldp_dual_adjacency — S14: basic and targeted discovery adjacencies plus TCP session

task ended failed: output error: [ab080fe0-335b-4cb0-b669-54066f0e59a2-0a67c38f-b2d6-4b22-86f0-d6fa04440a5a: validation failed: ldp: at least one event required]

### ldp_tcp_multi_session — S13: two independent parallel TCP/646 LDP sessions

task ended failed: output error: [27e859f4-b2d2-45e2-b9f3-7f647eee4480-41cdc324-10a0-4833-ab71-75f38683e2fb: validation failed: ldp: at least one event required]

