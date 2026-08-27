# mongodb Pcap Test Results

Cases: 13 — pass 12, fail 1, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| mongodb_bson_types | S3: OP_INSERT carrying all supported BSON basic types | pass | 8 | [pcap](mongodb/mongodb_bson_types.pcap) |
| mongodb_empty_boundary | S4: legal minimum five-byte empty BSON selector | pass | 8 | [pcap](mongodb/mongodb_empty_boundary.pcap) |
| mongodb_ipv6 | S5: IPv6 OP_QUERY and OP_REPLY preserve MongoDB header layout | pass | 9 | [pcap](mongodb/mongodb_ipv6.pcap) |
| mongodb_message_header | S7: all four little-endian message header fields | pass | 8 | [pcap](mongodb/mongodb_message_header.pcap) |
| mongodb_multi_session | S6: two independent sessions retain request and response correlation | fail | 9 | `mongodb/mongodb_multi_session.pcap` |
| mongodb_neg_bad_opcode | N4: unknown opcode is rejected | pass | 0 | [pcap]() |
| mongodb_neg_bson_length | N5: BSON length beyond message boundary is rejected | pass | 0 | [pcap]() |
| mongodb_neg_oversize | N3: messageLength beyond configured limit is rejected | pass | 0 | [pcap]() |
| mongodb_neg_short_length | N2: messageLength below header size is rejected | pass | 0 | [pcap]() |
| mongodb_neg_truncated_header | N1: header shorter than 16 bytes is rejected | pass | 0 | [pcap]() |
| mongodb_neg_udp_carrier | N6: UDP carrier is rejected | pass | 0 | [pcap]() |
| mongodb_query_reply | S1: OP_QUERY followed by OP_REPLY with responseTo correlation | pass | 9 | [pcap](mongodb/mongodb_query_reply.pcap) |
| mongodb_write_ops | S2: atomic legacy write and cursor operation messages | pass | 12 | [pcap](mongodb/mongodb_write_ops.pcap) |

## Failures

### mongodb_multi_session — S6: two independent sessions retain request and response correlation

verify: count: got 9 packets, want 18; field tcp.dstport: packet 0 out of range (file has 9 packets); field tcp.srcport: distinct values mismatch (want [12345 12346]; missing [12346]; unexpected [27017(x4)])

