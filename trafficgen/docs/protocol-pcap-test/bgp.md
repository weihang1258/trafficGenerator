# bgp Pcap Test Results

Cases: 19 — pass 2, fail 7, error 10

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| bgp_connect | S1: TCP/179 connect without BGP application events | error | 0 | `` |
| bgp_hold_time_zero | S6: OPEN hold time zero is observable and valid | error | 0 | `` |
| bgp_ipv4_nlri_32 | S7: IPv4 /32 NLRI prefix byte boundary | error | 0 | `` |
| bgp_ipv6_transport | S8: IPv6 TCP transport with RFC 4271 IPv4 BGP identifier | error | 0 | `` |
| bgp_keepalive_length_boundary | S10: minimum legal BGP length 19 KEEPALIVE | error | 0 | `` |
| bgp_multi_session | S9: two independent BGP sessions | error | 0 | `` |
| bgp_neg_address | N9: IPv6 NLRI in IPv4 profile rejected | fail | 0 | `` |
| bgp_neg_as | N7: My AS outside two-octet range rejected | pass | 0 | [pcap]() |
| bgp_neg_length | N4: invalid message length rejected | fail | 0 | `` |
| bgp_neg_marker | N3: non-all-ones marker rejected | fail | 0 | `` |
| bgp_neg_mp_reach_profile | N2: unimplemented MP_REACH IPv6 profile rejected | fail | 0 | `` |
| bgp_neg_state | N8: UPDATE before OPEN exchange rejected | fail | 0 | `` |
| bgp_neg_type | N5: unknown BGP message type rejected | fail | 0 | `` |
| bgp_neg_udp | N1: UDP carrier rejected | pass | 0 | [pcap]() |
| bgp_neg_version | N6: OPEN version other than 4 rejected | fail | 0 | `` |
| bgp_notification_hold_expired | S5: NOTIFICATION Hold Timer Expired then TCP termination | error | 0 | `` |
| bgp_open_keepalive | S2: OPEN exchange then bidirectional KEEPALIVE | error | 0 | `` |
| bgp_update_attributes | S3: IPv4 UPDATE with ORIGIN AS_PATH NEXT_HOP MED LOCAL_PREF COMMUNITIES | error | 0 | `` |
| bgp_update_withdraw | S4: UPDATE withdrawing an IPv4 /24 route | error | 0 | `` |

## Failures

### bgp_connect — S1: TCP/179 connect without BGP application events

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: bgp)

### bgp_hold_time_zero — S6: OPEN hold time zero is observable and valid

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: bgp)

### bgp_ipv4_nlri_32 — S7: IPv4 /32 NLRI prefix byte boundary

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: bgp)

### bgp_ipv6_transport — S8: IPv6 TCP transport with RFC 4271 IPv4 BGP identifier

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: bgp)

### bgp_keepalive_length_boundary — S10: minimum legal BGP length 19 KEEPALIVE

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: bgp)

### bgp_multi_session — S9: two independent BGP sessions

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: bgp)

### bgp_neg_address — N9: IPv6 NLRI in IPv4 profile rejected

rejected but error "failed to start any strategy (last failure: task validation failed: invalid protocol: bgp)" does not contain "address"

### bgp_neg_length — N4: invalid message length rejected

rejected but error "failed to start any strategy (last failure: task validation failed: invalid protocol: bgp)" does not contain "length"

### bgp_neg_marker — N3: non-all-ones marker rejected

rejected but error "failed to start any strategy (last failure: task validation failed: invalid protocol: bgp)" does not contain "marker"

### bgp_neg_mp_reach_profile — N2: unimplemented MP_REACH IPv6 profile rejected

rejected but error "failed to start any strategy (last failure: task validation failed: invalid protocol: bgp)" does not contain "profile"

### bgp_neg_state — N8: UPDATE before OPEN exchange rejected

rejected but error "failed to start any strategy (last failure: task validation failed: invalid protocol: bgp)" does not contain "state"

### bgp_neg_type — N5: unknown BGP message type rejected

rejected but error "failed to start any strategy (last failure: task validation failed: invalid protocol: bgp)" does not contain "type"

### bgp_neg_version — N6: OPEN version other than 4 rejected

rejected but error "failed to start any strategy (last failure: task validation failed: invalid protocol: bgp)" does not contain "version"

### bgp_notification_hold_expired — S5: NOTIFICATION Hold Timer Expired then TCP termination

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: bgp)

### bgp_open_keepalive — S2: OPEN exchange then bidirectional KEEPALIVE

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: bgp)

### bgp_update_attributes — S3: IPv4 UPDATE with ORIGIN AS_PATH NEXT_HOP MED LOCAL_PREF COMMUNITIES

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: bgp)

### bgp_update_withdraw — S4: UPDATE withdrawing an IPv4 /24 route

generate: failed to start any strategy (last failure: task validation failed: invalid protocol: bgp)

