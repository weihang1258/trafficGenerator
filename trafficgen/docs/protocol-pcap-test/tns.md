# tns Pcap Test Results

Cases: 12 — pass 12, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| tns_connect_accept | S1/T-TNS-S1: CONNECT→ACCEPT→TTC data; TCP 1521 | pass | 11 | [pcap](tns/tns_connect_accept.pcap) |
| tns_header_fields | S7/T-TNS-S7: complete public header fields and DATA flags | pass | 11 | [pcap](tns/tns_header_fields.pcap) |
| tns_ipv6_connect | S5/T-TNS-S5: IPv6 CONNECT→ACCEPT | pass | 9 | [pcap](tns/tns_ipv6_connect.pcap) |
| tns_multi_session | S6/T-TNS-S6: two independent CONNECT→ACCEPT sessions | pass | 18 | [pcap](tns/tns_multi_session.pcap) |
| tns_neg_checksum | N4: nonzero checksum conflicts with disabled mode | pass | 0 | [pcap]() |
| tns_neg_data_flags | N5: nonzero DATA flags rejected in v1 | pass | 0 | [pcap]() |
| tns_neg_length | N3: packet length below 8 rejected | pass | 0 | [pcap]() |
| tns_neg_packet_type | N2: unknown packet type rejected | pass | 0 | [pcap]() |
| tns_neg_udp | N1: UDP carrier rejected | pass | 0 | [pcap]() |
| tns_redirect | S3/T-TNS-S3: CONNECT→REDIRECT; no reconnect | pass | 9 | [pcap](tns/tns_redirect.pcap) |
| tns_refuse | S2/T-TNS-S2: CONNECT→REFUSE; no DATA | pass | 9 | [pcap](tns/tns_refuse.pcap) |
| tns_ttc_sqlnet_session | S4/T-TNS-S4: TTC and SQL*Net profile sequence, flags zero | pass | 13 | [pcap](tns/tns_ttc_sqlnet_session.pcap) |
