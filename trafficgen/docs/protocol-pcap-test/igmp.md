# igmp Pcap Test Results

Cases: 25 — pass 0, fail 8, error 17

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| igmp_ipv4_outer_invariants | IPv4 Protocol 2 TTL 1 and multicast destination | error | 0 | `` |
| igmp_multi_group_sessions | multiple sessions and groups | error | 0 | `` |
| igmp_neg_bad_checksum | bad IGMP checksum rejected | fail | 0 | `` |
| igmp_neg_invalid_profile_version | profile and message type mixed rejected | fail | 0 | `` |
| igmp_neg_invalid_v3_record | invalid v3 record type or truncated source list rejected | fail | 0 | `` |
| igmp_neg_ipv6 | IPv6 is N/A and rejected | fail | 0 | `` |
| igmp_neg_nonmulticast_destination | non-multicast destination rejected | fail | 0 | `` |
| igmp_neg_protocol_not_two | non-2 IPv4 protocol rejected | fail | 0 | `` |
| igmp_neg_query_source_count_length | v3 source count and encoded bytes mismatch rejected | fail | 0 | `` |
| igmp_neg_ttl_not_one | TTL other than one rejected | fail | 0 | `` |
| igmp_profile_matrix | v1/v2/v3 profile matrix | error | 0 | `` |
| igmp_retransmit_state | query/member state and retransmitted report | error | 0 | `` |
| igmp_v1_general_query | v1 General Query | error | 0 | `` |
| igmp_v1_report | v1 Membership Report | error | 0 | `` |
| igmp_v2_general_query | v2 General Query | error | 0 | `` |
| igmp_v2_group_specific_query | v2 Group-Specific Query | error | 0 | `` |
| igmp_v2_leave | v2 Leave Group | error | 0 | `` |
| igmp_v2_report | v2 Membership Report | error | 0 | `` |
| igmp_v3_allow_block_sources | v3 ALLOW_NEW_SOURCES and BLOCK_OLD_SOURCES | error | 0 | `` |
| igmp_v3_change_records | v3 mode-change records | error | 0 | `` |
| igmp_v3_exclude_record | v3 MODE_IS_EXCLUDE Group Record | error | 0 | `` |
| igmp_v3_general_query | v3 General Query | error | 0 | `` |
| igmp_v3_include_record | v3 MODE_IS_INCLUDE Group Record | error | 0 | `` |
| igmp_v3_query_boundaries | v3 MRC/QRV/QQIC/source-count boundaries | error | 0 | `` |
| igmp_v3_source_specific_query | v3 Source-Specific Query | error | 0 | `` |

## Failures

### igmp_ipv4_outer_invariants — IPv4 Protocol 2 TTL 1 and multicast destination

generate: layers: unknown layer "igmp" (position 1)

### igmp_multi_group_sessions — multiple sessions and groups

generate: layers: unknown layer "igmp" (position 1)

### igmp_neg_bad_checksum — bad IGMP checksum rejected

rejected but error "layers: unknown layer \"igmp\" (position 1)" does not contain "checksum"

### igmp_neg_invalid_profile_version — profile and message type mixed rejected

rejected but error "layers: unknown layer \"igmp\" (position 1)" does not contain "profile"

### igmp_neg_invalid_v3_record — invalid v3 record type or truncated source list rejected

rejected but error "layers: unknown layer \"igmp\" (position 1)" does not contain "record"

### igmp_neg_ipv6 — IPv6 is N/A and rejected

rejected but error "layers: unknown layer \"igmp\" (position 1)" does not contain "IPv6"

### igmp_neg_nonmulticast_destination — non-multicast destination rejected

rejected but error "layers: unknown layer \"igmp\" (position 1)" does not contain "multicast"

### igmp_neg_protocol_not_two — non-2 IPv4 protocol rejected

rejected but error "layers: unknown layer \"igmp\" (position 1)" does not contain "Protocol 2"

### igmp_neg_query_source_count_length — v3 source count and encoded bytes mismatch rejected

rejected but error "layers: unknown layer \"igmp\" (position 1)" does not contain "source count"

### igmp_neg_ttl_not_one — TTL other than one rejected

rejected but error "layers: unknown layer \"igmp\" (position 1)" does not contain "TTL"

### igmp_profile_matrix — v1/v2/v3 profile matrix

generate: layers: unknown layer "igmp" (position 1)

### igmp_retransmit_state — query/member state and retransmitted report

generate: layers: unknown layer "igmp" (position 1)

### igmp_v1_general_query — v1 General Query

generate: layers: unknown layer "igmp" (position 1)

### igmp_v1_report — v1 Membership Report

generate: layers: unknown layer "igmp" (position 1)

### igmp_v2_general_query — v2 General Query

generate: layers: unknown layer "igmp" (position 1)

### igmp_v2_group_specific_query — v2 Group-Specific Query

generate: layers: unknown layer "igmp" (position 1)

### igmp_v2_leave — v2 Leave Group

generate: layers: unknown layer "igmp" (position 1)

### igmp_v2_report — v2 Membership Report

generate: layers: unknown layer "igmp" (position 1)

### igmp_v3_allow_block_sources — v3 ALLOW_NEW_SOURCES and BLOCK_OLD_SOURCES

generate: layers: unknown layer "igmp" (position 1)

### igmp_v3_change_records — v3 mode-change records

generate: layers: unknown layer "igmp" (position 1)

### igmp_v3_exclude_record — v3 MODE_IS_EXCLUDE Group Record

generate: layers: unknown layer "igmp" (position 1)

### igmp_v3_general_query — v3 General Query

generate: layers: unknown layer "igmp" (position 1)

### igmp_v3_include_record — v3 MODE_IS_INCLUDE Group Record

generate: layers: unknown layer "igmp" (position 1)

### igmp_v3_query_boundaries — v3 MRC/QRV/QQIC/source-count boundaries

generate: layers: unknown layer "igmp" (position 1)

### igmp_v3_source_specific_query — v3 Source-Specific Query

generate: layers: unknown layer "igmp" (position 1)

