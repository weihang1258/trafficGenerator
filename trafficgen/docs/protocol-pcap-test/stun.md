# stun Pcap Test Results

Cases: 24 — pass 24, fail 0, error 0

| Case | Summary | Status | Packets | Pcap |
|------|---------|--------|---------|------|
| stun_attribute_padding | Attribute length and 32-bit zero padding | pass | 1 | [pcap](stun/stun_attribute_padding.pcap) |
| stun_auth_attributes | Binding request authentication context attributes | pass | 1 | [pcap](stun/stun_auth_attributes.pcap) |
| stun_binding_mapped_both | MAPPED-ADDRESS and XOR-MAPPED-ADDRESS comparison | pass | 2 | [pcap](stun/stun_binding_mapped_both.pcap) |
| stun_binding_tcp_request | TCP Binding request with STUN TCP message framing | pass | 8 | [pcap](stun/stun_binding_tcp_request.pcap) |
| stun_binding_tls_session | TLS carrier session; STUN remains encrypted without keys | pass | 15 | [pcap](stun/stun_binding_tls_session.pcap) |
| stun_binding_udp_error | UDP Binding error with ERROR-CODE and UNKNOWN-ATTRIBUTES | pass | 2 | [pcap](stun/stun_binding_udp_error.pcap) |
| stun_binding_udp_request | UDP/IPv4 Binding request with 20-byte header | pass | 1 | [pcap](stun/stun_binding_udp_request.pcap) |
| stun_binding_udp_success_ipv4 | UDP Binding success with IPv4 XOR/MAPPED address | pass | 2 | [pcap](stun/stun_binding_udp_success_ipv4.pcap) |
| stun_binding_udp_success_ipv6 | UDP/IPv6 Binding success with IPv6 XOR address | pass | 2 | [pcap](stun/stun_binding_udp_success_ipv6.pcap) |
| stun_integrity_fingerprint | MESSAGE-INTEGRITY and FINGERPRINT computed at runtime | pass | 1 | [pcap](stun/stun_integrity_fingerprint.pcap) |
| stun_ipv6_address_attributes | IPv6 outer carrier and both address-family attributes | pass | 2 | [pcap](stun/stun_ipv6_address_attributes.pcap) |
| stun_multi_transaction_tcp | Multiple transactions on one TCP session | pass | 11 | [pcap](stun/stun_multi_transaction_tcp.pcap) |
| stun_multi_transaction_udp | Multiple isolated UDP Binding transactions | pass | 4 | [pcap](stun/stun_multi_transaction_udp.pcap) |
| stun_neg_attribute_length | Attribute length or padding overruns message | pass | 0 | [pcap]() |
| stun_neg_bad_cookie | Magic Cookie is invalid | pass | 0 | [pcap]() |
| stun_neg_bad_integrity | MESSAGE-INTEGRITY verification fails | pass | 0 | [pcap]() |
| stun_neg_header_short | STUN header shorter than 20 bytes | pass | 0 | [pcap]() |
| stun_neg_length_alignment | Message Length is not 4-byte aligned | pass | 0 | [pcap]() |
| stun_neg_length_overrun | Message Length exceeds payload | pass | 0 | [pcap]() |
| stun_neg_transport_mismatch | Carrier and STUN framing mismatch | pass | 0 | [pcap]() |
| stun_neg_turn_boundary | TURN or RFC 5780 method enters Binding profile | pass | 0 | [pcap]() |
| stun_neg_type_reserved_bits | Reserved message type bits set | pass | 0 | [pcap]() |
| stun_retransmission | UDP retransmission repeats the same transaction | pass | 3 | [pcap](stun/stun_retransmission.pcap) |
| stun_rfc8489_profile | RFC 8489 compatible Binding profile | pass | 1 | [pcap](stun/stun_rfc8489_profile.pcap) |
