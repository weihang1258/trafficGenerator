# pim Pcap Test Results

Cases: 24 — pass 0, fail 7, error 17

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| pim_neg_address_family | IPv4 PIM profile cannot encode IPv6 group/source | fail | 0 | `` |
| pim_neg_checksum | Malformed PIM checksum is rejected | fail | 0 | `` |
| pim_neg_df_profile | DF Election requires independent Bidirectional PIM profile | fail | 0 | `` |
| pim_neg_ipv6_profile | IPv6 PIM is a separate unsupported profile | fail | 0 | `` |
| pim_neg_length | Inconsistent IPv4/PIM length is rejected | fail | 0 | `` |
| pim_neg_ssm_rp | SSM cannot carry RP/Register or wildcard state | fail | 0 | `` |
| pim_neg_type | Unknown or mismatched PIM message type is rejected | fail | 0 | `` |
| pim_sm_assert | PIM-SM Assert with group/source and metrics | error | 0 | `` |
| pim_sm_bootstrap_rp_set | PIM-SM Bootstrap with BSR and RP set priorities | error | 0 | `` |
| pim_sm_candidate_rp_adv | PIM-SM Candidate-RP Advertisement | error | 0 | `` |
| pim_sm_checksum_length | PIM-SM checksum and IPv4 total-length boundary | error | 0 | `` |
| pim_sm_dr_election | PIM-SM DR election inputs from three neighbors | error | 0 | `` |
| pim_sm_hello_holdtime | PIM-SM Hello with explicit Holdtime and interval | error | 0 | `` |
| pim_sm_hello_options | PIM-SM Hello options including LAN Prune Delay, DR priority and Generation ID | error | 0 | `` |
| pim_sm_hello_zero_holdtime | PIM-SM Hello Holdtime zero immediate-expiry boundary | error | 0 | `` |
| pim_sm_joinprune_multi_group | PIM-SM Join/Prune with wildcard and source trees in two groups | error | 0 | `` |
| pim_sm_joinprune_retransmit | PIM-SM explicit Join/Prune retransmission | error | 0 | `` |
| pim_sm_joinprune_source | PIM-SM Join/Prune concrete (S,G) join and prune | error | 0 | `` |
| pim_sm_joinprune_wildcard | PIM-SM Join/Prune wildcard (*,G) | error | 0 | `` |
| pim_sm_multi_neighbor_state | PIM-SM independent neighbor and tree state events | error | 0 | `` |
| pim_sm_register | PIM-SM Register with explicit inner IPv4 packet profile | error | 0 | `` |
| pim_sm_register_stop | PIM-SM Register-Stop with explicit group and source | error | 0 | `` |
| pim_ssm_joinprune_sg | PIM-SSM RFC 4607 concrete (S,G) Join/Prune without RP | error | 0 | `` |
| pim_ssm_multi_group | PIM-SSM independent concrete source trees for multiple groups | error | 0 | `` |

## Failures

### pim_neg_address_family — IPv4 PIM profile cannot encode IPv6 group/source

rejected but error "layers: unknown layer \"pim\" (position 1)" does not contain "address"

### pim_neg_checksum — Malformed PIM checksum is rejected

rejected but error "layers: unknown layer \"pim\" (position 1)" does not contain "checksum"

### pim_neg_df_profile — DF Election requires independent Bidirectional PIM profile

rejected but error "layers: unknown layer \"pim\" (position 1)" does not contain "df"

### pim_neg_ipv6_profile — IPv6 PIM is a separate unsupported profile

rejected but error "layers: unknown layer \"ipv6\" (position 0)" does not contain "profile"

### pim_neg_length — Inconsistent IPv4/PIM length is rejected

rejected but error "layers: unknown layer \"pim\" (position 1)" does not contain "length"

### pim_neg_ssm_rp — SSM cannot carry RP/Register or wildcard state

rejected but error "layers: unknown layer \"pim\" (position 1)" does not contain "ssm"

### pim_neg_type — Unknown or mismatched PIM message type is rejected

rejected but error "layers: unknown layer \"pim\" (position 1)" does not contain "type"

### pim_sm_assert — PIM-SM Assert with group/source and metrics

generate: layers: unknown layer "pim" (position 1)

### pim_sm_bootstrap_rp_set — PIM-SM Bootstrap with BSR and RP set priorities

generate: layers: unknown layer "pim" (position 1)

### pim_sm_candidate_rp_adv — PIM-SM Candidate-RP Advertisement

generate: layers: unknown layer "pim" (position 1)

### pim_sm_checksum_length — PIM-SM checksum and IPv4 total-length boundary

generate: layers: unknown layer "pim" (position 1)

### pim_sm_dr_election — PIM-SM DR election inputs from three neighbors

generate: layers: unknown layer "pim" (position 1)

### pim_sm_hello_holdtime — PIM-SM Hello with explicit Holdtime and interval

generate: layers: unknown layer "pim" (position 1)

### pim_sm_hello_options — PIM-SM Hello options including LAN Prune Delay, DR priority and Generation ID

generate: layers: unknown layer "pim" (position 1)

### pim_sm_hello_zero_holdtime — PIM-SM Hello Holdtime zero immediate-expiry boundary

generate: layers: unknown layer "pim" (position 1)

### pim_sm_joinprune_multi_group — PIM-SM Join/Prune with wildcard and source trees in two groups

generate: layers: unknown layer "pim" (position 1)

### pim_sm_joinprune_retransmit — PIM-SM explicit Join/Prune retransmission

generate: layers: unknown layer "pim" (position 1)

### pim_sm_joinprune_source — PIM-SM Join/Prune concrete (S,G) join and prune

generate: layers: unknown layer "pim" (position 1)

### pim_sm_joinprune_wildcard — PIM-SM Join/Prune wildcard (*,G)

generate: layers: unknown layer "pim" (position 1)

### pim_sm_multi_neighbor_state — PIM-SM independent neighbor and tree state events

generate: layers: unknown layer "pim" (position 1)

### pim_sm_register — PIM-SM Register with explicit inner IPv4 packet profile

generate: layers: unknown layer "pim" (position 1)

### pim_sm_register_stop — PIM-SM Register-Stop with explicit group and source

generate: layers: unknown layer "pim" (position 1)

### pim_ssm_joinprune_sg — PIM-SSM RFC 4607 concrete (S,G) Join/Prune without RP

generate: layers: unknown layer "pim" (position 1)

### pim_ssm_multi_group — PIM-SSM independent concrete source trees for multiple groups

generate: layers: unknown layer "pim" (position 1)

