# ldp Pcap Test Results

Cases: 25 — pass 0, fail 11, error 14

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| ldp_address_ipv4 | S3: IPv4 Address message after session initialization | error | 0 | `` |
| ldp_dual_adjacency | S14: basic and targeted discovery adjacencies plus TCP session | error | 0 | `` |
| ldp_label_mapping_host32 | S8: IPv4 /32 host-route Label Mapping | error | 0 | `` |
| ldp_label_mapping_ipv4 | S4: IPv4 /24 Label Mapping with Generic Label | error | 0 | `` |
| ldp_label_release_ipv4 | S7: IPv4 /24 Label Release after Mapping | error | 0 | `` |
| ldp_label_request_ipv4 | S5: IPv4 /24 Label Request | error | 0 | `` |
| ldp_label_withdraw_ipv4 | S6: IPv4 /24 Label Withdraw after Mapping | error | 0 | `` |
| ldp_neg_carrier | N1: LDP without UDP or TCP carrier | fail | 0 | `` |
| ldp_neg_checksum | N11: invalid transport checksum rejected | fail | 0 | `` |
| ldp_neg_ipv6_profile | N3: IPv6 transport/profile is not silently mixed into IPv4 | fail | 0 | `` |
| ldp_neg_label_bounds | N8: Generic Label exceeds 20-bit bound | fail | 0 | `` |
| ldp_neg_message_length | N5: declared message length mismatch | fail | 0 | `` |
| ldp_neg_pdu_length | N4: declared PDU length mismatch | fail | 0 | `` |
| ldp_neg_port | N2: discovery with non-646 UDP port | fail | 0 | `` |
| ldp_neg_prefix_bounds | N9: IPv4 FEC prefix length exceeds 32 | fail | 0 | `` |
| ldp_neg_state | N10: KeepAlive before Initialization | fail | 0 | `` |
| ldp_neg_tlv_length | N6: declared TLV length mismatch | fail | 0 | `` |
| ldp_neg_unknown_message | N7: unknown LDP message type | fail | 0 | `` |
| ldp_notification_shutdown | S11: Notification status event terminates the LDP session | error | 0 | `` |
| ldp_ordered_dod_allocation | S12: downstream-on-demand ordered label request/mapping | error | 0 | `` |
| ldp_tcp_initialization | S1: TCP/646 session Initialization in both directions | error | 0 | `` |
| ldp_tcp_keepalive | S2: Initialization followed by bidirectional KeepAlive | error | 0 | `` |
| ldp_tcp_multi_session | S13: two independent parallel TCP/646 LDP sessions | error | 0 | `` |
| ldp_udp_parallel_hellos | S10: basic discovery Hellos in both directions | error | 0 | `` |
| ldp_udp_targeted_hello | S9: targeted UDP/646 Hello with transport address | error | 0 | `` |

## Failures

### ldp_address_ipv4 — S3: IPv4 Address message after session initialization

generate: invalid or missing protocol: ldp

### ldp_dual_adjacency — S14: basic and targeted discovery adjacencies plus TCP session

generate: invalid or missing protocol: ldp

### ldp_label_mapping_host32 — S8: IPv4 /32 host-route Label Mapping

generate: invalid or missing protocol: ldp

### ldp_label_mapping_ipv4 — S4: IPv4 /24 Label Mapping with Generic Label

generate: invalid or missing protocol: ldp

### ldp_label_release_ipv4 — S7: IPv4 /24 Label Release after Mapping

generate: invalid or missing protocol: ldp

### ldp_label_request_ipv4 — S5: IPv4 /24 Label Request

generate: invalid or missing protocol: ldp

### ldp_label_withdraw_ipv4 — S6: IPv4 /24 Label Withdraw after Mapping

generate: invalid or missing protocol: ldp

### ldp_neg_carrier — N1: LDP without UDP or TCP carrier

rejected but error "invalid or missing protocol: ldp" does not contain "carrier"

### ldp_neg_checksum — N11: invalid transport checksum rejected

rejected but error "invalid or missing protocol: ldp" does not contain "checksum"

### ldp_neg_ipv6_profile — N3: IPv6 transport/profile is not silently mixed into IPv4

rejected but error "invalid or missing protocol: ldp" does not contain "profile"

### ldp_neg_label_bounds — N8: Generic Label exceeds 20-bit bound

rejected but error "invalid or missing protocol: ldp" does not contain "label"

### ldp_neg_message_length — N5: declared message length mismatch

rejected but error "invalid or missing protocol: ldp" does not contain "message"

### ldp_neg_pdu_length — N4: declared PDU length mismatch

rejected but error "invalid or missing protocol: ldp" does not contain "pdu"

### ldp_neg_port — N2: discovery with non-646 UDP port

rejected but error "invalid or missing protocol: ldp" does not contain "port"

### ldp_neg_prefix_bounds — N9: IPv4 FEC prefix length exceeds 32

rejected but error "invalid or missing protocol: ldp" does not contain "prefix"

### ldp_neg_state — N10: KeepAlive before Initialization

rejected but error "invalid or missing protocol: ldp" does not contain "state"

### ldp_neg_tlv_length — N6: declared TLV length mismatch

rejected but error "invalid or missing protocol: ldp" does not contain "tlv"

### ldp_neg_unknown_message — N7: unknown LDP message type

rejected but error "invalid or missing protocol: ldp" does not contain "unknown"

### ldp_notification_shutdown — S11: Notification status event terminates the LDP session

generate: invalid or missing protocol: ldp

### ldp_ordered_dod_allocation — S12: downstream-on-demand ordered label request/mapping

generate: invalid or missing protocol: ldp

### ldp_tcp_initialization — S1: TCP/646 session Initialization in both directions

generate: invalid or missing protocol: ldp

### ldp_tcp_keepalive — S2: Initialization followed by bidirectional KeepAlive

generate: invalid or missing protocol: ldp

### ldp_tcp_multi_session — S13: two independent parallel TCP/646 LDP sessions

generate: invalid or missing protocol: ldp

### ldp_udp_parallel_hellos — S10: basic discovery Hellos in both directions

generate: invalid or missing protocol: ldp

### ldp_udp_targeted_hello — S9: targeted UDP/646 Hello with transport address

generate: invalid or missing protocol: ldp

