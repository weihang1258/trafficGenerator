# igmp Pcap Test Results

Cases: 25 — pass 25, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| igmp_ipv4_outer_invariants | IPv4 carrier invariants (proto 2 / TTL 1 / group dst) | pass | 1 | [pcap](igmp/igmp_ipv4_outer_invariants.pcap) |
| igmp_multi_group_sessions | multi-session a/b/c across v1/v2/v3 | pass | 4 | [pcap](igmp/igmp_multi_group_sessions.pcap) |
| igmp_neg_bad_checksum | injected bad checksum rejected | pass | 0 | [pcap]() |
| igmp_neg_invalid_profile_version | v1 + leave (profile/kind mismatch) rejected | pass | 0 | [pcap]() |
| igmp_neg_invalid_v3_record | numeric record_type rejected at decode | pass | 0 | [pcap]() |
| igmp_neg_ipv6 | IPv6 is N/A and rejected | pass | 0 | [pcap]() |
| igmp_neg_nonmulticast_destination | unicast destination rejected | pass | 0 | [pcap]() |
| igmp_neg_protocol_not_two | non-2 IPv4 protocol rejected | pass | 0 | [pcap]() |
| igmp_neg_query_source_count_length | source_count != len(sources) rejected | pass | 0 | [pcap]() |
| igmp_neg_ttl_not_one | TTL != 1 rejected | pass | 0 | [pcap]() |
| igmp_profile_matrix | v1/v2/v3 profile matrix (3 events) | pass | 3 | [pcap](igmp/igmp_profile_matrix.pcap) |
| igmp_retransmit_state | querying → member, retransmit identical report | pass | 3 | [pcap](igmp/igmp_retransmit_state.pcap) |
| igmp_v1_general_query | v1 General Query | pass | 1 | [pcap](igmp/igmp_v1_general_query.pcap) |
| igmp_v1_report | v1 Membership Report | pass | 1 | [pcap](igmp/igmp_v1_report.pcap) |
| igmp_v2_general_query | v2 General Query | pass | 1 | [pcap](igmp/igmp_v2_general_query.pcap) |
| igmp_v2_group_specific_query | v2 Group-Specific Query | pass | 1 | [pcap](igmp/igmp_v2_group_specific_query.pcap) |
| igmp_v2_leave | v2 Leave Group (224.0.0.2) | pass | 1 | [pcap](igmp/igmp_v2_leave.pcap) |
| igmp_v2_report | v2 Membership Report | pass | 1 | [pcap](igmp/igmp_v2_report.pcap) |
| igmp_v3_allow_block_sources | v3 ALLOW_NEW_SOURCES + BLOCK_OLD_SOURCES | pass | 1 | [pcap](igmp/igmp_v3_allow_block_sources.pcap) |
| igmp_v3_change_records | v3 mode-change records (empty + single source) | pass | 1 | [pcap](igmp/igmp_v3_change_records.pcap) |
| igmp_v3_exclude_record | v3 MODE_IS_EXCLUDE Group Record | pass | 1 | [pcap](igmp/igmp_v3_exclude_record.pcap) |
| igmp_v3_general_query | v3 General Query (MRC/QRV/QQIC) | pass | 1 | [pcap](igmp/igmp_v3_general_query.pcap) |
| igmp_v3_include_record | v3 MODE_IS_INCLUDE Group Record | pass | 1 | [pcap](igmp/igmp_v3_include_record.pcap) |
| igmp_v3_query_boundaries | v3 boundaries: MRC=255 float code, QRV=7, QQIC=255, 3 sources | pass | 1 | [pcap](igmp/igmp_v3_query_boundaries.pcap) |
| igmp_v3_source_specific_query | v3 Source-Specific Query (S/QRV, 2 sources) | pass | 1 | [pcap](igmp/igmp_v3_source_specific_query.pcap) |
