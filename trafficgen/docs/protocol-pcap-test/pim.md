# pim Pcap Test Results

Cases: 24 — pass 24, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| pim_neg_address_family | IPv4 PIM profile cannot encode IPv6 group/source | pass | 0 | [pcap]() |
| pim_neg_checksum | Malformed PIM checksum is rejected | pass | 0 | [pcap]() |
| pim_neg_df_profile | DF Election requires independent Bidirectional PIM profile | pass | 0 | [pcap]() |
| pim_neg_ipv6_profile | IPv6 PIM is a separate unsupported profile | pass | 0 | [pcap]() |
| pim_neg_length | Inconsistent IPv4/PIM length is rejected | pass | 0 | [pcap]() |
| pim_neg_ssm_rp | SSM cannot carry RP/Register or wildcard state | pass | 0 | [pcap]() |
| pim_neg_type | Unknown or mismatched PIM message type is rejected | pass | 0 | [pcap]() |
| pim_sm_assert | PIM-SM Assert with group/source and metrics | pass | 1 | [pcap](pim/pim_sm_assert.pcap) |
| pim_sm_bootstrap_rp_set | PIM-SM Bootstrap with BSR and RP set priorities | pass | 1 | [pcap](pim/pim_sm_bootstrap_rp_set.pcap) |
| pim_sm_candidate_rp_adv | PIM-SM Candidate-RP Advertisement | pass | 1 | [pcap](pim/pim_sm_candidate_rp_adv.pcap) |
| pim_sm_checksum_length | PIM-SM checksum and IPv4 total-length boundary | pass | 1 | [pcap](pim/pim_sm_checksum_length.pcap) |
| pim_sm_dr_election | PIM-SM DR election inputs from three neighbors | pass | 3 | [pcap](pim/pim_sm_dr_election.pcap) |
| pim_sm_hello_holdtime | PIM-SM Hello with explicit Holdtime and interval | pass | 1 | [pcap](pim/pim_sm_hello_holdtime.pcap) |
| pim_sm_hello_options | PIM-SM Hello options including LAN Prune Delay, DR priority and Generation ID | pass | 1 | [pcap](pim/pim_sm_hello_options.pcap) |
| pim_sm_hello_zero_holdtime | PIM-SM Hello Holdtime zero immediate-expiry boundary | pass | 1 | [pcap](pim/pim_sm_hello_zero_holdtime.pcap) |
| pim_sm_joinprune_multi_group | PIM-SM Join/Prune with wildcard and source trees in two groups | pass | 1 | [pcap](pim/pim_sm_joinprune_multi_group.pcap) |
| pim_sm_joinprune_retransmit | PIM-SM explicit Join/Prune retransmission | pass | 2 | [pcap](pim/pim_sm_joinprune_retransmit.pcap) |
| pim_sm_joinprune_source | PIM-SM Join/Prune concrete (S,G) join and prune | pass | 1 | [pcap](pim/pim_sm_joinprune_source.pcap) |
| pim_sm_joinprune_wildcard | PIM-SM Join/Prune wildcard (*,G) | pass | 1 | [pcap](pim/pim_sm_joinprune_wildcard.pcap) |
| pim_sm_multi_neighbor_state | PIM-SM independent neighbor and tree state events | pass | 6 | [pcap](pim/pim_sm_multi_neighbor_state.pcap) |
| pim_sm_register | PIM-SM Register with explicit inner IPv4 packet profile | pass | 1 | [pcap](pim/pim_sm_register.pcap) |
| pim_sm_register_stop | PIM-SM Register-Stop with explicit group and source | pass | 1 | [pcap](pim/pim_sm_register_stop.pcap) |
| pim_ssm_joinprune_sg | PIM-SSM RFC 4607 concrete (S,G) Join/Prune without RP | pass | 1 | [pcap](pim/pim_ssm_joinprune_sg.pcap) |
| pim_ssm_multi_group | PIM-SSM independent concrete source trees for multiple groups | pass | 2 | [pcap](pim/pim_ssm_multi_group.pcap) |
